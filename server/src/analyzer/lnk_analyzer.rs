/// lnk_analyzer.rs — Analyse de raccourcis Windows .lnk (NOUVEAU).
/// Extrait les strings et détecte les arguments suspects (LNK = vecteur
/// de phishing classique : raccourci → powershell encodé).
use crate::types::{IoC, LnkInfo, Severity};

const SUSPICIOUS_LNK_PATTERNS: &[(&str, &str, Severity)] = &[
    ("powershell", "PowerShell invoqué depuis un raccourci", Severity::High),
    ("-encodedcommand", "Commande PowerShell encodée", Severity::Critical),
    ("-enc ", "Commande PowerShell encodée (forme courte)", Severity::Critical),
    ("-windowstyle hidden", "Exécution en fenêtre cachée", Severity::High),
    ("cmd.exe /c", "Commande CMD embarquée", Severity::High),
    ("cmd /c", "Commande CMD embarquée", Severity::High),
    ("mshta", "Exécution HTA depuis raccourci", Severity::Critical),
    ("wscript", "Exécution de script WSH", Severity::High),
    ("cscript", "Exécution de script WSH", Severity::High),
    ("rundll32", "Exécution DLL depuis raccourci", Severity::High),
    ("certutil", "Téléchargement/décodage via certutil", Severity::Critical),
    ("bitsadmin", "Téléchargement via BITS", Severity::Critical),
    ("http://", "URL embarquée dans le raccourci", Severity::Medium),
    ("https://", "URL embarquée dans le raccourci", Severity::Medium),
    ("%temp%", "Référence au dossier temporaire", Severity::Medium),
    ("%appdata%", "Référence au dossier AppData", Severity::Medium),
];

/// Extrait les strings UTF-16LE et ASCII du .lnk puis cherche les patterns.
pub fn analyze(data: &[u8]) -> (LnkInfo, Vec<IoC>) {
    // Strings ASCII
    let mut text = String::new();
    let mut current = Vec::new();
    for &b in data {
        if (0x20..=0x7E).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= 4 {
                text.push_str(&String::from_utf8_lossy(&current));
                text.push('\n');
            }
            current.clear();
        }
    }
    if current.len() >= 4 {
        text.push_str(&String::from_utf8_lossy(&current));
    }

    // Strings UTF-16LE (paths Windows dans les LNK)
    let mut wide = String::new();
    let mut wcurrent: Vec<u16> = Vec::new();
    for pair in data.chunks_exact(2) {
        let c = u16::from_le_bytes([pair[0], pair[1]]);
        if (0x20..=0x7E).contains(&c) {
            wcurrent.push(c);
        } else {
            if wcurrent.len() >= 4 {
                wide.push_str(&String::from_utf16_lossy(&wcurrent));
                wide.push('\n');
            }
            wcurrent.clear();
        }
    }
    if wcurrent.len() >= 4 {
        wide.push_str(&String::from_utf16_lossy(&wcurrent));
    }

    let combined = format!("{text}\n{wide}");
    let combined_lower = combined.to_lowercase();

    let mut suspicious_args = Vec::new();
    let mut ioc_list = Vec::new();

    for (pattern, description, severity) in SUSPICIOUS_LNK_PATTERNS {
        if combined_lower.contains(pattern) {
            suspicious_args.push(pattern.to_string());
            ioc_list.push(IoC {
                ioc_type: "Raccourci LNK".to_string(),
                value: pattern.to_string(),
                severity: severity.clone(),
                description: description.to_string(),
            });
        }
    }

    // Indice de cible : première ligne contenant un chemin exe
    let target_hint = combined
        .lines()
        .find(|l| l.to_lowercase().contains(".exe") || l.to_lowercase().contains(".bat"))
        .map(|l| l.trim().chars().take(200).collect())
        .unwrap_or_else(|| "Cible non identifiée".to_string());

    (LnkInfo { target_hint, suspicious_args }, ioc_list)
}
