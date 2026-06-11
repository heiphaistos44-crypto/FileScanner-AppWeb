/// script_parser.rs — Analyse lexicale de scripts (étendu vs desktop).
/// Windows : BAT/PS1/VBS/JS/HTA — Unix : SH/BASH/PY/PL/PHP/RB.
use std::sync::LazyLock;

use regex::Regex;

use crate::types::{IoC, ScriptInfo, ScriptMatchedLine, Severity};

static RE_BASE64: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{64,}={0,2}").unwrap());

static RE_CONCAT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"['"][^'"]{1,3}['"]\s*\+\s*['"]"#).unwrap());

static RE_HEX_BLOB: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\\x[0-9a-fA-F]{2}){16,}").unwrap());

const DANGEROUS_CALLS: &[(&str, &str, Severity)] = &[
    // ── PowerShell / Windows ──
    ("Invoke-Expression", "Exécution de code dynamique PowerShell", Severity::High),
    ("IEX", "Alias Invoke-Expression (obfuscation PS)", Severity::High),
    ("DownloadString", "Téléchargement de payload réseau", Severity::High),
    ("DownloadFile", "Téléchargement de fichier réseau", Severity::High),
    ("WebClient", "Accès HTTP sortant", Severity::Medium),
    ("Invoke-WebRequest", "Accès HTTP sortant", Severity::Medium),
    ("Start-Process", "Lancement de processus", Severity::Medium),
    ("cmd.exe", "Shell CMD invoqué depuis script", Severity::Medium),
    ("powershell.exe", "PowerShell invoqué depuis script", Severity::Medium),
    ("reg.exe", "Modification du registre Windows", Severity::High),
    ("schtasks", "Création de tâche planifiée", Severity::High),
    ("net user", "Gestion de comptes utilisateurs", Severity::High),
    ("net localgroup", "Modification des groupes locaux", Severity::High),
    ("netsh", "Modification du pare-feu / réseau", Severity::High),
    ("wmic", "Exécution WMI", Severity::Medium),
    ("certutil", "Possible décodage/téléchargement via certutil", Severity::High),
    ("bitsadmin", "Téléchargement via BITS", Severity::High),
    ("mshta", "Exécution HTA (bypass)", Severity::Critical),
    ("regsvr32", "Exécution COM via regsvr32 (bypass)", Severity::Critical),
    ("rundll32", "Exécution DLL via rundll32", Severity::High),
    // ── Étendus Windows ──
    ("vssadmin delete", "Suppression des shadow copies (ransomware)", Severity::Critical),
    ("wevtutil cl", "Effacement des journaux d'événements", Severity::Critical),
    ("bcdedit", "Modification de la configuration de démarrage", Severity::High),
    ("Set-MpPreference", "Désactivation de Windows Defender", Severity::Critical),
    ("Add-MpPreference", "Exclusion Windows Defender ajoutée", Severity::High),
    ("AmsiUtils", "Tentative de bypass AMSI", Severity::Critical),
    ("amsiInitFailed", "Bypass AMSI (patch mémoire)", Severity::Critical),
    ("FromBase64String", "Décodage Base64 (payload caché)", Severity::Medium),
    ("Reflection.Assembly", "Chargement d'assembly en mémoire", Severity::High),
    ("-WindowStyle Hidden", "Exécution fenêtre cachée", Severity::High),
    ("-ExecutionPolicy Bypass", "Contournement de la politique d'exécution PS", Severity::High),
    ("New-Object Net.Sockets", "Socket réseau brut (reverse shell ?)", Severity::High),
    ("attrib +h", "Masquage de fichiers", Severity::Medium),
    ("icacls", "Modification des permissions fichiers", Severity::Medium),
    ("taskkill", "Arrêt forcé de processus", Severity::Medium),
    // ── Unix / cross-platform ──
    ("curl ", "Téléchargement réseau (curl)", Severity::Medium),
    ("wget ", "Téléchargement réseau (wget)", Severity::Medium),
    ("/dev/tcp/", "Reverse shell bash (/dev/tcp)", Severity::Critical),
    ("nc -e", "Netcat avec exécution (reverse shell)", Severity::Critical),
    ("bash -i", "Shell bash interactif (reverse shell probable)", Severity::High),
    ("chmod +x", "Rend un fichier exécutable", Severity::Medium),
    ("crontab", "Persistance via cron", Severity::High),
    ("base64 -d", "Décodage Base64 (payload caché)", Severity::Medium),
    ("eval(", "Exécution de code dynamique", Severity::High),
    ("exec(", "Exécution de code dynamique", Severity::High),
    ("os.system", "Exécution de commande système (Python)", Severity::High),
    ("subprocess.", "Lancement de processus (Python)", Severity::Medium),
    ("shell_exec", "Exécution shell (PHP)", Severity::High),
    ("passthru", "Exécution shell (PHP webshell ?)", Severity::High),
    ("assert(", "Exécution dynamique PHP (webshell)", Severity::High),
    ("$_POST[", "Entrée POST exécutée (webshell PHP ?)", Severity::Medium),
    ("ld_preload", "Injection de bibliothèque (LD_PRELOAD)", Severity::High),
    ("/etc/passwd", "Accès au fichier des comptes", Severity::Medium),
    ("/etc/shadow", "Accès aux mots de passe système", Severity::High),
    ("history -c", "Effacement de l'historique shell", Severity::High),
];

const BASE64_MIN_LENGTH: usize = 64;

/// Analyse lexicale d'un script.
pub fn analyze(file_name: &str, content: &str) -> (ScriptInfo, Vec<IoC>) {
    let script_type = detect_script_type(file_name, content);
    let mut dangerous_calls = Vec::new();
    let mut ioc_list = Vec::new();
    let mut matched_lines: Vec<ScriptMatchedLine> = Vec::new();

    let content_lower = content.to_lowercase();

    for (pattern, description, severity) in DANGEROUS_CALLS {
        if content_lower.contains(&pattern.to_lowercase()) {
            dangerous_calls.push(pattern.to_string());
            ioc_list.push(IoC {
                ioc_type: "Appel dangereux".to_string(),
                value: pattern.to_string(),
                severity: severity.clone(),
                description: description.to_string(),
            });
            let pat_lower = pattern.to_lowercase();
            for (i, line) in content.lines().enumerate() {
                if line.to_lowercase().contains(&pat_lower) {
                    let trimmed: String = line.trim().chars().take(200).collect();
                    matched_lines.push(ScriptMatchedLine {
                        line_number: i + 1,
                        pattern: pattern.to_string(),
                        line_content: trimmed,
                    });
                    if matched_lines.iter().filter(|m| m.pattern == *pattern).count() >= 3 {
                        break;
                    }
                }
            }
        }
    }

    let base64_blobs_count = count_base64_blobs(content);
    let base64_samples = get_base64_samples(content);
    let hex_blobs = RE_HEX_BLOB.is_match(content);
    let obfuscation_detected = base64_blobs_count > 0 || hex_blobs || detect_obfuscation(content);

    if base64_blobs_count > 0 {
        ioc_list.push(IoC {
            ioc_type: "Obfuscation".to_string(),
            value: format!("{} blob(s) Base64", base64_blobs_count),
            severity: Severity::High,
            description: "Blobs Base64 détectés — payload potentiellement caché".to_string(),
        });
    }

    if hex_blobs {
        ioc_list.push(IoC {
            ioc_type: "Obfuscation".to_string(),
            value: "Blob hexadécimal (\\x..)".to_string(),
            severity: Severity::High,
            description: "Shellcode encodé en hexadécimal probable".to_string(),
        });
    }

    if detect_obfuscation(content) {
        ioc_list.push(IoC {
            ioc_type: "Obfuscation".to_string(),
            value: "Caractères d'échappement anormaux".to_string(),
            severity: Severity::Medium,
            description: "Pattern d'obfuscation par concaténation ou échappement détecté".to_string(),
        });
    }

    (
        ScriptInfo {
            obfuscation_detected,
            dangerous_calls,
            base64_blobs_count,
            script_type,
            matched_lines,
            base64_samples,
        },
        ioc_list,
    )
}

fn detect_script_type(file_name: &str, content: &str) -> String {
    let ext = file_name.rsplit('.').next().unwrap_or("").to_uppercase();
    if ext.is_empty() || ext == file_name.to_uppercase() {
        // Pas d'extension → shebang
        if let Some(first) = content.lines().next() {
            if first.starts_with("#!") {
                return format!("SHEBANG ({})", first.trim().chars().take(40).collect::<String>());
            }
        }
        return "UNKNOWN".to_string();
    }
    ext
}

fn count_base64_blobs(content: &str) -> usize {
    RE_BASE64
        .find_iter(content)
        .filter(|m| m.len() >= BASE64_MIN_LENGTH)
        .count()
}

fn get_base64_samples(content: &str) -> Vec<String> {
    RE_BASE64
        .find_iter(content)
        .filter(|m| m.len() >= BASE64_MIN_LENGTH)
        .take(5)
        .map(|m| {
            let s = m.as_str();
            if s.len() > 80 {
                format!("{}…", &s[..80])
            } else {
                s.to_string()
            }
        })
        .collect()
}

fn detect_obfuscation(content: &str) -> bool {
    let caret_density =
        content.chars().filter(|&c| c == '^').count() as f64 / content.len().max(1) as f64;

    let concat_ps =
        content.contains("` ") || content.contains("`\"") || RE_CONCAT.is_match(content);

    caret_density > 0.05 || concat_ps
}
