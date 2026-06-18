/// main.rs — FileScanner Web : API axum + frontend statique.
/// POST /api/scan : multipart (file) → ScanResult JSON complet.

mod analyzer;
mod api;
mod error;
mod scanner;
mod types;

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::anyhow;
use axum::{
    extract::{DefaultBodyLimit, Multipart, State},
    http::{header, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use tokio::sync::Semaphore;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::KeyExtractor, GovernorError, GovernorLayer,
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
};

use scanner::clamav_db::ClamavDb;
use scanner::pipeline::{self, ScanContext};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_UPLOAD_BYTES: usize = 100 * 1024 * 1024; // 100 MB
const MAX_INFLIGHT: usize = 2;
const SCAN_TIMEOUT_SECS: u64 = 120;

struct AppState {
    clamav: Option<ClamavDb>,
    vt_api_key: String,
    scan_permits: Semaphore,
}

// ─── Extraction IP cliente ────────────────────────────────────────────────────

#[derive(Clone)]
struct ClientIpExtractor;

impl KeyExtractor for ClientIpExtractor {
    type Key = IpAddr;

    fn extract<B>(&self, req: &Request<B>) -> Result<Self::Key, GovernorError> {
        let header_ip = |name: &str| -> Option<IpAddr> {
            req.headers()
                .get(name)?
                .to_str()
                .ok()?
                .split(',')
                .next()?
                .trim()
                .parse()
                .ok()
        };

        // Priorité : cf-connecting-ip (Cloudflare) → x-real-ip (nginx/proxy direct)
        // Ne pas utiliser x-forwarded-for (premier segment spoofable par le client).
        header_ip("cf-connecting-ip")
            .or_else(|| header_ip("x-real-ip"))
            .or_else(|| {
                req.extensions()
                    .get::<axum::extract::ConnectInfo<SocketAddr>>()
                    .map(|ci| ci.0.ip())
            })
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

// ─── Erreur API ───────────────────────────────────────────────────────────────

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

fn bad_request(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Ne pas exposer : version exacte, statut VT, compteurs de signatures ClamAV
    Json(serde_json::json!({
        "status": "ok",
        "av_enhanced": state.clamav.is_some() || !state.vt_api_key.is_empty(),
    }))
}

async fn scan(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Response, ApiError> {
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut file_name = String::from("unknown");

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| bad_request(format!("Multipart invalide : {e}")))?
    {
        if field.name() == Some("file") {
            file_name = field.file_name().unwrap_or("unknown").to_string();
            let data = field
                .bytes()
                .await
                .map_err(|e| bad_request(format!("Lecture fichier : {e}")))?;
            file_bytes = Some(data.to_vec());
        }
    }

    let bytes = file_bytes.ok_or_else(|| bad_request("Champ 'file' manquant"))?;
    if bytes.is_empty() {
        return Err(bad_request("Fichier vide"));
    }

    // Nom de fichier nettoyé (pas de path, pas de null bytes ni caractères de contrôle)
    let file_name = file_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("unknown")
        .chars()
        .filter(|c| !matches!(c, '\0' | '\x01'..='\x1f'))
        .take(255)
        .collect::<String>();

    let _permit = state
        .scan_permits
        .acquire()
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "Arrêt en cours".into()))?;

    let ctx = ScanContext {
        clamav: state.clamav.as_ref(),
        vt_api_key: &state.vt_api_key,
    };

    let result = tokio::time::timeout(
        Duration::from_secs(SCAN_TIMEOUT_SECS),
        pipeline::scan_bytes(&bytes, &file_name, &ctx),
    )
    .await
    .map_err(|_| {
        ApiError(
            StatusCode::REQUEST_TIMEOUT,
            "Scan interrompu : timeout dépassé (2 minutes)".into(),
        )
    })?;

    Ok(Json(result).into_response())
}

// ─── main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(3004);
    let static_dir = std::env::var("STATIC_DIR").unwrap_or_else(|_| "../web/dist".into());
    let allowed_origin = std::env::var("ALLOWED_ORIGIN")
        .unwrap_or_else(|_| "https://filescanner-app.heiphaistos.org".into());
    let vt_api_key = std::env::var("VT_API_KEY").unwrap_or_default();
    let clamav_dir = std::env::var("CLAMAV_DB_DIR").unwrap_or_default();

    // ClamAV : chargement au démarrage si répertoire fourni
    let clamav = if clamav_dir.is_empty() {
        tracing::info!("ClamAV désactivé (CLAMAV_DB_DIR non défini)");
        None
    } else {
        match ClamavDb::load(&PathBuf::from(&clamav_dir)) {
            Ok(db) => {
                let st = db.status();
                if st.loaded {
                    tracing::info!(
                        "ClamAV chargé : {} MD5 + {} SHA256 depuis {}",
                        st.md5_count, st.sha256_count, clamav_dir
                    );
                    Some(db)
                } else {
                    tracing::warn!("ClamAV : aucune signature trouvée dans {clamav_dir}");
                    None
                }
            }
            Err(e) => {
                tracing::warn!("ClamAV non chargé : {e}");
                None
            }
        }
    };

    if vt_api_key.is_empty() {
        tracing::info!("VirusTotal désactivé (VT_API_KEY non défini)");
    } else {
        tracing::info!("VirusTotal activé");
    }

    let state = Arc::new(AppState {
        clamav,
        vt_api_key,
        scan_permits: Semaphore::new(MAX_INFLIGHT),
    });

    // Rate-limit : burst 10, recharge 1 toutes les 6 s (≈ 10 scans/min/IP)
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(6)
            .burst_size(10)
            .key_extractor(ClientIpExtractor)
            .finish()
            .ok_or_else(|| anyhow!("Config rate-limit invalide"))?,
    );

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::exact(
            allowed_origin.parse::<HeaderValue>()
                .map_err(|e| anyhow!("ALLOWED_ORIGIN invalide : {e}"))?,
        ));

    // Security headers appliqués à toutes les réponses
    let csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'";
    let sec_headers = tower::ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(csp),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
        ));

    // En axum, le DERNIER .layer() est le plus externe (voit la requête en premier).
    // Ordre d'exécution : DefaultBodyLimit → GovernorLayer → TimeoutLayer → handler
    // DefaultBodyLimit en dernier = rejet des corps >100MB avant que GovernorLayer
    // ne consomme un quota de rate-limit sur une requête invalide.
    let api = Router::new()
        .route("/api/scan", post(scan))
        .route("/api/health", get(health))
        .layer(cors)
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(150)))
        .layer(GovernorLayer { config: governor_conf })
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES))
        .with_state(state);

    let index = format!("{static_dir}/index.html");
    let static_service = ServeDir::new(&static_dir).fallback(ServeFile::new(&index));

    let app = api.fallback_service(static_service).layer(sec_headers);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("FileScanner Web v{VERSION} — écoute sur http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Arrêt demandé");
    })
    .await?;

    Ok(())
}
