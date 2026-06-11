/// strings.rs — Extraction d'IOCs depuis les strings du fichier (NOUVEAU).
/// URLs, IPs, emails, wallets BTC, adresses .onion, clés de registre.
use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::types::{ExtractedIoCs, IoC, Severity};

static RE_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,200}"#).unwrap()
});

static RE_IP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
        .unwrap()
});

static RE_EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap()
});

static RE_BTC: LazyLock<Regex> = LazyLock::new(|| {
    // Legacy (1/3) + Bech32 (bc1)
    Regex::new(r"\b(bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b").unwrap()
});

static RE_ONION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[a-z2-7]{16,56}\.onion\b").unwrap()
});

static RE_REGISTRY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\[\w\\ .\-()%{}]{3,120}").unwrap()
});

/// Domaines à ignorer (présents dans tout binaire légitime)
const URL_ALLOWLIST: &[&str] = &[
    "schemas.openxmlformats.org", "schemas.microsoft.com", "www.w3.org",
    "purl.org", "ns.adobe.com", "openxmlformats.org", "xml.org",
    "mozilla.org", "apache.org", "iso.org", "crl.microsoft.com",
    "ocsp.digicert.com", "crl.digicert.com", "sectigo.com", "globalsign.com",
    "verisign.com", "godaddy.com", "comodoca.com", "usertrust.com",
    "letsencrypt.org", "rust-lang.org", "github.com/rust-lang",
];

/// Extrait les chaînes ASCII imprimables ≥ 6 chars (limite : 4 Mo analysés).
fn extract_ascii_strings(data: &[u8]) -> String {
    const MAX_ANALYZE: usize = 4 * 1024 * 1024;
    let slice = &data[..data.len().min(MAX_ANALYZE)];

    let mut out = String::with_capacity(64 * 1024);
    let mut current = Vec::new();

    for &b in slice {
        if (0x20..=0x7E).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= 6 {
                out.push_str(&String::from_utf8_lossy(&current));
                out.push('\n');
            }
            current.clear();
        }
    }
    if current.len() >= 6 {
        out.push_str(&String::from_utf8_lossy(&current));
    }
    out
}

fn dedup_take(set: BTreeSet<String>, max: usize) -> Vec<String> {
    set.into_iter().take(max).collect()
}

pub fn extract_iocs(data: &[u8]) -> (ExtractedIoCs, Vec<IoC>) {
    let text = extract_ascii_strings(data);

    let urls: BTreeSet<String> = RE_URL
        .find_iter(&text)
        .map(|m| m.as_str().to_string())
        .filter(|u| !URL_ALLOWLIST.iter().any(|allow| u.contains(allow)))
        .collect();

    let ips: BTreeSet<String> = RE_IP
        .find_iter(&text)
        .map(|m| m.as_str().to_string())
        .filter(|ip| {
            // Filtre versions (0.0.0.0, 127.0.0.1, 255.255.255.255) et IPs réservées triviales
            !matches!(ip.as_str(), "0.0.0.0" | "127.0.0.1" | "255.255.255.255" | "1.1.1.1" | "8.8.8.8")
                && !ip.starts_with("0.")
        })
        .collect();

    let emails: BTreeSet<String> = RE_EMAIL.find_iter(&text).map(|m| m.as_str().to_string()).collect();
    let btc: BTreeSet<String> = RE_BTC.find_iter(&text).map(|m| m.as_str().to_string()).collect();
    let onion: BTreeSet<String> = RE_ONION.find_iter(&text).map(|m| m.as_str().to_string()).collect();
    let registry: BTreeSet<String> = RE_REGISTRY.find_iter(&text).map(|m| m.as_str().to_string()).collect();

    let mut ioc_list = Vec::new();

    if !onion.is_empty() {
        ioc_list.push(IoC {
            ioc_type: "Réseau Tor".to_string(),
            value: onion.iter().next().cloned().unwrap_or_default(),
            severity: Severity::High,
            description: format!("{} adresse(s) .onion — communication Tor cachée", onion.len()),
        });
    }
    if !btc.is_empty() {
        ioc_list.push(IoC {
            ioc_type: "Crypto wallet".to_string(),
            value: btc.iter().next().cloned().unwrap_or_default(),
            severity: Severity::Medium,
            description: format!("{} adresse(s) Bitcoin — possible ransomware/mineur", btc.len()),
        });
    }
    if urls.len() > 10 {
        ioc_list.push(IoC {
            ioc_type: "Réseau".to_string(),
            value: format!("{} URLs", urls.len()),
            severity: Severity::Low,
            description: "Nombre élevé d'URLs embarquées".to_string(),
        });
    }
    // Clé de registre Run = persistance
    for key in &registry {
        let k = key.to_lowercase();
        if k.contains("currentversion\\run") || k.contains("winlogon") {
            ioc_list.push(IoC {
                ioc_type: "Persistance".to_string(),
                value: key.chars().take(80).collect(),
                severity: Severity::Medium,
                description: "Référence à une clé de démarrage automatique".to_string(),
            });
            break;
        }
    }

    (
        ExtractedIoCs {
            urls: dedup_take(urls, 50),
            ips: dedup_take(ips, 30),
            emails: dedup_take(emails, 20),
            btc_wallets: dedup_take(btc, 10),
            onion_addresses: dedup_take(onion, 10),
            registry_keys: dedup_take(registry, 20),
        },
        ioc_list,
    )
}
