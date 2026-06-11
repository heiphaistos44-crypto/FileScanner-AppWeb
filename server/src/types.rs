/// types.rs — Structures du rapport de scan (étendu vs desktop v1.1.0).
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Verdict {
    Safe,
    Suspicious,
    Malicious,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Hashes étendus : MD5 + SHA-1 + SHA-256 + SHA-512.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinarySection {
    pub name: String,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub entropy: f64,
}

/// Infos binaire unifiées : PE (Windows), ELF (Linux), Mach-O (macOS).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    /// "PE" | "ELF" | "Mach-O"
    pub format: String,
    pub is_64bit: bool,
    pub is_signed: bool,
    pub sections: Vec<BinarySection>,
    pub imports: Vec<String>,
    pub entry_point: u64,
    pub entropy_max: f64,
    pub suspicious_imports: Vec<String>,
    pub is_packed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptMatchedLine {
    pub line_number: usize,
    pub pattern: String,
    pub line_content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptInfo {
    pub obfuscation_detected: bool,
    pub dangerous_calls: Vec<String>,
    pub base64_blobs_count: usize,
    pub script_type: String,
    pub matched_lines: Vec<ScriptMatchedLine>,
    pub base64_samples: Vec<String>,
}

/// Entrée d'archive inspectée.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub name: String,
    pub size: u64,
    pub compressed_size: u64,
    pub is_executable: bool,
    pub is_encrypted: bool,
}

/// Résultat d'inspection d'archive (ZIP, JAR, APK, Office).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveInfo {
    pub archive_type: String,
    pub total_entries: usize,
    pub entries: Vec<ArchiveEntry>,
    pub has_nested_executable: bool,
    pub has_double_extension: bool,
    pub has_encrypted_entries: bool,
    /// Macros VBA détectées (Office)
    pub has_vba_macros: bool,
    pub vba_keywords: Vec<String>,
}

/// Menaces PDF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfInfo {
    pub has_javascript: bool,
    pub has_open_action: bool,
    pub has_launch_action: bool,
    pub has_embedded_files: bool,
    pub has_acroform: bool,
    pub suspicious_count: usize,
}

/// Raccourci Windows .lnk analysé.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnkInfo {
    pub target_hint: String,
    pub suspicious_args: Vec<String>,
}

/// IOCs extraits des strings (URLs, IPs, emails, wallets…).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedIoCs {
    pub urls: Vec<String>,
    pub ips: Vec<String>,
    pub emails: Vec<String>,
    pub btc_wallets: Vec<String>,
    pub onion_addresses: Vec<String>,
    pub registry_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtResult {
    pub positives: u32,
    pub total: u32,
    pub permalink: String,
    pub scan_date: String,
    pub detection_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub description: String,
    pub severity: Severity,
    pub matched_strings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoC {
    pub ioc_type: String,
    pub value: String,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClamavResult {
    pub malware_name: String,
    pub database: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub file_name: String,
    pub file_size: u64,
    pub mime_type: String,
    pub category: String,
    pub hashes: Hashes,
    pub global_entropy: f64,
    pub verdict: Verdict,
    pub verdict_score: u8,
    pub binary_info: Option<BinaryInfo>,
    pub script_info: Option<ScriptInfo>,
    pub archive_info: Option<ArchiveInfo>,
    pub pdf_info: Option<PdfInfo>,
    pub lnk_info: Option<LnkInfo>,
    pub extracted_iocs: ExtractedIoCs,
    pub virustotal: Option<VtResult>,
    pub clamav: Option<ClamavResult>,
    pub yara_matches: Vec<YaraMatch>,
    pub ioc_list: Vec<IoC>,
    pub scanned_at: String,
}
