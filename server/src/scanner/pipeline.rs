/// pipeline.rs — Orchestration du scan (bytes-based, étendu vs desktop).
/// Étapes : hashes → MIME → analyseur spécialisé (PE/ELF/Mach-O/script/
/// archive/Office/PDF/LNK) → strings IOC → YARA → ClamAV → VirusTotal → score.
use crate::analyzer::{archive, binary_parser, entropy, hash, lnk_analyzer, mime, pdf_analyzer, script_parser, strings};
use crate::api::virustotal;
use crate::scanner::clamav_db::ClamavDb;
use crate::scanner::yara_engine;
use crate::types::{
    ArchiveInfo, BinaryInfo, ClamavResult, IoC, PdfInfo, ScanResult, ScriptInfo, Severity, Verdict,
};

pub struct ScanContext<'a> {
    pub clamav: Option<&'a ClamavDb>,
    pub vt_api_key: &'a str,
}

pub async fn scan_bytes(
    raw_bytes: &[u8],
    file_name: &str,
    ctx: &ScanContext<'_>,
) -> ScanResult {
    let file_size = raw_bytes.len() as u64;

    // 1. Hashes (MD5 + SHA-1 + SHA-256 + SHA-512)
    let hashes = hash::compute(raw_bytes);

    // 2. MIME réel + catégorie
    let mime_type = mime::detect(raw_bytes, file_name);
    let category = mime::categorize(&mime_type, raw_bytes, file_name);

    // 3. Entropie globale
    let global_entropy = entropy::shannon_entropy(raw_bytes);

    // 4. Analyseur spécialisé selon catégorie
    let mut binary_info: Option<BinaryInfo> = None;
    let mut script_info: Option<ScriptInfo> = None;
    let mut archive_info: Option<ArchiveInfo> = None;
    let mut pdf_info: Option<PdfInfo> = None;
    let mut lnk_info = None;
    let mut ioc_list: Vec<IoC> = Vec::new();

    match category {
        mime::FileCategory::Pe | mime::FileCategory::Elf | mime::FileCategory::MachO => {
            match binary_parser::parse(raw_bytes) {
                Ok((info, iocs)) => {
                    ioc_list.extend(iocs);
                    binary_info = Some(info);
                }
                Err(e) => tracing::warn!("Analyse binaire échouée pour {file_name} : {e}"),
            }
        }
        mime::FileCategory::Script => {
            if let Ok(content) = std::str::from_utf8(raw_bytes) {
                let (info, iocs) = script_parser::analyze(file_name, content);
                ioc_list.extend(iocs);
                script_info = Some(info);
            }
        }
        mime::FileCategory::Archive => {
            if let Some((info, iocs)) = archive::analyze_zip(raw_bytes, "ZIP") {
                ioc_list.extend(iocs);
                archive_info = Some(info);
            }
        }
        mime::FileCategory::OfficeDoc => {
            // OOXML = ZIP → inspection macros VBA
            if let Some((info, iocs)) = archive::analyze_zip(raw_bytes, "Office OOXML") {
                ioc_list.extend(iocs);
                archive_info = Some(info);
            }
        }
        mime::FileCategory::Pdf => {
            let (info, iocs) = pdf_analyzer::analyze(raw_bytes);
            ioc_list.extend(iocs);
            pdf_info = Some(info);
        }
        mime::FileCategory::Lnk => {
            let (info, iocs) = lnk_analyzer::analyze(raw_bytes);
            ioc_list.extend(iocs);
            lnk_info = Some(info);
        }
        _ => {}
    }

    // 5. Extraction IOCs depuis les strings (tous types)
    let (extracted_iocs, string_iocs) = strings::extract_iocs(raw_bytes);
    ioc_list.extend(string_iocs);

    // 6. YARA scan (38 règles) — singleton global, pas de reconstruction
    let yara_matches = yara_engine::global().scan(raw_bytes);

    // 7. ClamAV (si base chargée)
    let clamav = ctx.clamav.and_then(|db| {
        let hit = db.check_md5(&hashes.md5).or_else(|| db.check_sha256(&hashes.sha256));
        hit.map(|m| {
            ioc_list.push(IoC {
                ioc_type: "ClamAV".to_string(),
                value: m.malware_name.clone(),
                severity: Severity::Critical,
                description: format!("Détecté par {} (base ClamAV)", m.database),
            });
            ClamavResult {
                malware_name: m.malware_name,
                database: m.database,
            }
        })
    });

    // 8. VirusTotal (clé serveur via env)
    let vt = if !ctx.vt_api_key.is_empty() {
        match virustotal::lookup(&hashes.sha256, ctx.vt_api_key).await {
            Ok(result) => Some(result),
            Err(crate::error::ScanError::Internal(msg)) if msg.contains("inconnu") => None,
            Err(e) => {
                tracing::warn!("VirusTotal lookup échoué : {e}");
                None
            }
        }
    } else {
        None
    };

    // 9. Score agrégé
    let verdict_score = compute_score(
        binary_info.as_ref(),
        script_info.as_ref(),
        archive_info.as_ref(),
        pdf_info.as_ref(),
        lnk_info.as_ref(),
        vt.as_ref(),
        &yara_matches,
        clamav.is_some(),
        &extracted_iocs,
    );

    let verdict = determine_verdict(verdict_score);

    ScanResult {
        file_name: file_name.to_string(),
        file_size,
        mime_type,
        category: category.as_str().to_string(),
        hashes,
        global_entropy,
        verdict,
        verdict_score,
        binary_info,
        script_info,
        archive_info,
        pdf_info,
        lnk_info,
        extracted_iocs,
        virustotal: vt,
        clamav,
        yara_matches,
        ioc_list,
        scanned_at: chrono::Utc::now().to_rfc3339(),
    }
}

#[allow(clippy::too_many_arguments)]
fn compute_score(
    binary_info: Option<&BinaryInfo>,
    script_info: Option<&ScriptInfo>,
    archive_info: Option<&ArchiveInfo>,
    pdf_info: Option<&PdfInfo>,
    lnk_info: Option<&crate::types::LnkInfo>,
    vt: Option<&crate::types::VtResult>,
    yara_matches: &[crate::types::YaraMatch],
    clamav_hit: bool,
    extracted: &crate::types::ExtractedIoCs,
) -> u8 {
    let mut score: u32 = 0;

    // ClamAV hit → malveillant certain
    if clamav_hit {
        score = score.max(95);
    }

    // VT : poids le plus fort
    if let Some(vt) = vt {
        if vt.positives >= 10 {
            score = score.max(95);
        } else if vt.positives >= 3 {
            score = score.max(85);
        } else if vt.positives >= 1 {
            score = score.max(60);
        }
    }

    // YARA — additif plafonné
    for m in yara_matches {
        let delta: u32 = match m.severity {
            Severity::Critical => 35,
            Severity::High => 20,
            Severity::Medium => 10,
            Severity::Low => 5,
        };
        score = (score + delta).min(100);
    }

    // Binaire (PE/ELF/Mach-O)
    if let Some(bin) = binary_info {
        if bin.entropy_max > 7.8 {
            score = (score + 20).min(100);
        } else if bin.entropy_max > 7.5 {
            score = (score + 10).min(100);
        } else if bin.entropy_max > 7.2 {
            score = (score + 5).min(100);
        }
        if !bin.suspicious_imports.is_empty() {
            let critical_imports = &[
                "CreateRemoteThread", "WriteProcessMemory",
                "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
                "QueueUserAPC", "ptrace", "memfd_create",
            ];
            let high_imports = &[
                "VirtualAllocEx", "SetWindowsHookEx", "URLDownloadToFile", "WinExec",
                "mprotect", "dlopen",
            ];
            let import_score: u32 = bin.suspicious_imports.iter().map(|imp| {
                if critical_imports.iter().any(|s| imp.contains(s)) { 20 }
                else if high_imports.iter().any(|s| imp.contains(s)) { 10 }
                else { 0 }
            }).sum::<u32>().min(40);
            score = (score + import_score).min(100);
        }
    }

    // Script
    if let Some(script) = script_info {
        if script.obfuscation_detected {
            score = score.max(60);
        }
        let call_score = (script.dangerous_calls.len() as u32 * 8).min(60);
        score = score.max(call_score);
    }

    // Archive
    if let Some(arc) = archive_info {
        if arc.has_double_extension {
            score = score.max(85);
        }
        if arc.has_vba_macros {
            let dangerous_kw = arc.vba_keywords.iter().any(|k| {
                matches!(k.as_str(), "Shell" | "WScript.Shell" | "powershell" | "cmd /c" | "cmd.exe" | "URLDownloadToFile" | "XMLHTTP")
            });
            score = score.max(if dangerous_kw { 80 } else { 45 });
        }
        if arc.has_nested_executable && arc.has_encrypted_entries {
            // Exécutable dans archive chiffrée = évasion AV classique
            score = score.max(70);
        } else if arc.has_nested_executable {
            score = (score + 15).min(100);
        }
    }

    // PDF
    if let Some(pdf) = pdf_info {
        if pdf.has_launch_action {
            score = score.max(80);
        }
        if pdf.has_javascript && pdf.has_open_action {
            score = score.max(75);
        } else if pdf.has_javascript {
            score = score.max(45);
        }
        score = (score + (pdf.suspicious_count as u32) * 5).min(100);
    }

    // LNK
    if let Some(lnk) = lnk_info {
        let critical_args = lnk.suspicious_args.iter().filter(|a| {
            matches!(a.as_str(), "-encodedcommand" | "-enc " | "mshta" | "certutil" | "bitsadmin")
        }).count();
        if critical_args > 0 {
            score = score.max(85);
        } else {
            let arg_score = (lnk.suspicious_args.len() as u32 * 12).min(60);
            score = score.max(arg_score);
        }
    }

    // IOCs réseau cachés
    if !extracted.onion_addresses.is_empty() {
        score = (score + 15).min(100);
    }
    if !extracted.btc_wallets.is_empty() && yara_matches.iter().any(|m| m.rule_name.starts_with("Ransomware")) {
        score = score.max(90);
    }

    score.min(100) as u8
}

fn determine_verdict(score: u8) -> Verdict {
    match score {
        0..=25 => Verdict::Safe,
        26..=64 => Verdict::Suspicious,
        _ => Verdict::Malicious,
    }
}
