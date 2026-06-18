/// virustotal.rs — Lookup VirusTotal v3 (repris du desktop, clé côté serveur).
use std::sync::OnceLock;
use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;

use crate::error::ScanError;
use crate::types::VtResult;

/// Client HTTP partagé — une seule instance pour réutiliser le pool de connexions.
static VT_CLIENT: OnceLock<Client> = OnceLock::new();

fn vt_client() -> Result<&'static Client, ScanError> {
    if let Some(c) = VT_CLIENT.get() {
        return Ok(c);
    }
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| ScanError::Internal(format!("Impossible de créer le client HTTP VirusTotal : {e}")))?;
    Ok(VT_CLIENT.get_or_init(|| client))
}

const VT_API_BASE: &str = "https://www.virustotal.com/api/v3";
const MAX_RETRIES: u32 = 3;

#[derive(Deserialize)]
struct VtResponse {
    data: VtData,
}

#[derive(Deserialize)]
struct VtData {
    attributes: VtAttributes,
}

#[derive(Deserialize)]
struct VtAttributes {
    last_analysis_stats: VtStats,
    last_analysis_results: Option<std::collections::HashMap<String, VtEngineResult>>,
    last_analysis_date: Option<i64>,
}

#[derive(Deserialize)]
struct VtStats {
    malicious: u32,
    suspicious: u32,
    undetected: u32,
    #[serde(default)]
    harmless: u32,
}

#[derive(Deserialize)]
struct VtEngineResult {
    category: String,
    result: Option<String>,
}

async fn with_backoff<F, Fut, T>(mut f: F) -> Result<T, ScanError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, ScanError>>,
{
    for attempt in 0..MAX_RETRIES {
        match f().await {
            Ok(v) => return Ok(v),
            Err(ScanError::RateLimited) if attempt < MAX_RETRIES - 1 => {
                let delay_ms = 500 * 2u64.pow(attempt);
                tracing::warn!(
                    "VT quota dépassé (429), tentative {}/{} — attente {}ms",
                    attempt + 1, MAX_RETRIES, delay_ms
                );
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            Err(e) => return Err(e),
        }
    }
    Err(ScanError::RateLimited)
}

pub async fn lookup(sha256: &str, api_key: &str) -> Result<VtResult, ScanError> {
    if api_key.is_empty() {
        return Err(ScanError::Internal("Clé API absente".to_string()));
    }
    // Validation stricte : SHA-256 = 64 hex lowercase uniquement (défense en profondeur)
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ScanError::Internal("Hash SHA-256 invalide".to_string()));
    }

    let client = vt_client()?;
    let response = with_backoff(|| {
        let client = client.clone();
        let url = format!("{}/files/{}", VT_API_BASE, sha256);
        let key = api_key.to_string();
        async move {
            let resp = client
                .get(&url)
                .header("x-apikey", &key)
                .send()
                .await
                .map_err(ScanError::HttpError)?;

            match resp.status().as_u16() {
                429 => Err(ScanError::RateLimited),
                404 => Err(ScanError::Internal("Fichier inconnu de VirusTotal".to_string())),
                s if s >= 400 => Err(ScanError::Internal(format!("VirusTotal API erreur HTTP {s}"))),
                _ => Ok(resp),
            }
        }
    })
    .await?;

    let vt: VtResponse = response.json().await?;
    let stats = &vt.data.attributes.last_analysis_stats;
    let total = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;

    let detection_names: Vec<String> = vt
        .data
        .attributes
        .last_analysis_results
        .unwrap_or_default()
        .values()
        .filter(|r| r.category == "malicious")
        .filter_map(|r| r.result.clone())
        .take(15)
        .collect();

    let scan_date = vt
        .data
        .attributes
        .last_analysis_date
        .map(|ts| {
            use chrono::TimeZone;
            chrono::Utc
                .timestamp_opt(ts, 0)
                .single()
                .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_default()
        })
        .unwrap_or_default();

    Ok(VtResult {
        positives: stats.malicious,
        total,
        permalink: format!("https://www.virustotal.com/gui/file/{}", sha256),
        scan_date,
        detection_names,
    })
}
