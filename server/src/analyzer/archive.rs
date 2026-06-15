/// archive.rs — Inspection d'archives ZIP et dérivés (NOUVEAU).
/// ZIP / JAR / APK / Office OOXML : liste des entrées, exécutables imbriqués,
/// doubles extensions, entrées chiffrées, macros VBA.
use std::io::{Cursor, Read};

use crate::types::{ArchiveEntry, ArchiveInfo, IoC, Severity};

const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "scr", "com", "pif", "cpl", "msi", "bat", "cmd", "ps1",
    "vbs", "js", "jse", "wsf", "hta", "jar", "elf", "sh", "bin", "lnk",
];

/// Mots-clés VBA auto-exécution + actions dangereuses
const VBA_KEYWORDS: &[&str] = &[
    "AutoOpen", "Auto_Open", "AutoExec", "AutoClose", "Document_Open",
    "Workbook_Open", "Workbook_Activate", "Document_Close",
    "Shell", "CreateObject", "WScript.Shell", "Wscript.shell",
    "URLDownloadToFile", "XMLHTTP", "ADODB.Stream", "powershell",
    "cmd /c", "cmd.exe", "Environ", "CallByName", "ExecuteExcel4Macro",
];

const MAX_ENTRIES_LISTED: usize = 100;
const MAX_VBA_SCAN_BYTES: u64 = 5 * 1024 * 1024;
/// Limite décompression totale : protège contre les ZIP bombs (ex. 42.zip)
const MAX_TOTAL_UNCOMPRESSED: u64 = 200 * 1024 * 1024; // 200 MB

pub fn analyze_zip(data: &[u8], archive_type: &str) -> Option<(ArchiveInfo, Vec<IoC>)> {
    let cursor = Cursor::new(data);
    let mut zip = zip::ZipArchive::new(cursor).ok()?;

    let total_entries = zip.len();
    let mut entries = Vec::new();
    let mut has_nested_executable = false;
    let mut has_double_extension = false;
    let mut has_encrypted_entries = false;
    let mut has_vba_macros = false;
    let mut vba_keywords: Vec<String> = Vec::new();
    let mut ioc_list = Vec::new();
    let mut total_uncompressed: u64 = 0;

    for i in 0..total_entries {
        let Ok(entry) = zip.by_index(i) else { continue };

        // Anti ZIP bomb : cumul des tailles décompressées
        total_uncompressed = total_uncompressed
            .checked_add(entry.size())
            .unwrap_or(u64::MAX);
        if total_uncompressed > MAX_TOTAL_UNCOMPRESSED {
            tracing::warn!(
                "ZIP bomb détectée : taille décompressée cumulée > {} MB — archive rejetée",
                MAX_TOTAL_UNCOMPRESSED / (1024 * 1024)
            );
            return None;
        }

        let name = entry.name().to_string();
        let lower = name.to_lowercase();

        let ext = lower.rsplit('.').next().unwrap_or("");
        let is_executable = EXECUTABLE_EXTENSIONS.contains(&ext) && !entry.is_dir();
        let is_encrypted = entry.encrypted();

        if is_executable {
            has_nested_executable = true;
        }
        if is_encrypted {
            has_encrypted_entries = true;
        }

        // Double extension : facture.pdf.exe, photo.jpg.scr…
        let parts: Vec<&str> = lower.rsplit('/').next().unwrap_or("").split('.').collect();
        if parts.len() >= 3 {
            let middle_ext = parts[parts.len() - 2];
            let final_ext = parts[parts.len() - 1];
            let document_exts = ["pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "mp4", "mp3"];
            if document_exts.contains(&middle_ext) && EXECUTABLE_EXTENSIONS.contains(&final_ext) {
                has_double_extension = true;
                ioc_list.push(IoC {
                    ioc_type: "Archive".to_string(),
                    value: name.chars().take(80).collect(),
                    severity: Severity::Critical,
                    description: "Double extension trompeuse dans l'archive".to_string(),
                });
            }
        }

        // Macros VBA : vbaProject.bin présent (docm/xlsm ou docx piégé)
        if lower.ends_with("vbaproject.bin") {
            has_vba_macros = true;
            // Lire les métadonnées AVANT le rebind mutable
            let vba_size = entry.size();
            let vba_compressed_size = entry.compressed_size();
            // Scan des mots-clés dans le blob OLE (strings brutes)
            if vba_size <= MAX_VBA_SCAN_BYTES {
                let mut entry = entry; // rebind mutable pour lecture
                let mut buf = Vec::new();
                if entry.read_to_end(&mut buf).is_ok() {
                    for kw in VBA_KEYWORDS {
                        if buf
                            .windows(kw.len())
                            .any(|w| w.eq_ignore_ascii_case(kw.as_bytes()))
                        {
                            vba_keywords.push(kw.to_string());
                        }
                    }
                }
            }
            if entries.len() < MAX_ENTRIES_LISTED {
                entries.push(ArchiveEntry {
                    name,
                    size: vba_size,
                    compressed_size: vba_compressed_size,
                    is_executable: false,
                    is_encrypted: false,
                });
            }
            continue;
        }

        if entries.len() < MAX_ENTRIES_LISTED {
            entries.push(ArchiveEntry {
                name,
                size: entry.size(),
                compressed_size: entry.compressed_size(),
                is_executable,
                is_encrypted,
            });
        }
    }

    if has_nested_executable {
        ioc_list.push(IoC {
            ioc_type: "Archive".to_string(),
            value: "Exécutable imbriqué".to_string(),
            severity: Severity::High,
            description: "L'archive contient un ou plusieurs fichiers exécutables".to_string(),
        });
    }
    if has_encrypted_entries {
        ioc_list.push(IoC {
            ioc_type: "Archive".to_string(),
            value: "Entrées chiffrées".to_string(),
            severity: Severity::Medium,
            description: "Archive protégée par mot de passe — technique d'évasion antivirus courante".to_string(),
        });
    }
    if has_vba_macros {
        let sev = if vba_keywords.iter().any(|k| {
            matches!(k.as_str(), "Shell" | "WScript.Shell" | "powershell" | "cmd /c" | "cmd.exe" | "URLDownloadToFile")
        }) {
            Severity::Critical
        } else {
            Severity::High
        };
        ioc_list.push(IoC {
            ioc_type: "Macro VBA".to_string(),
            value: if vba_keywords.is_empty() {
                "vbaProject.bin".to_string()
            } else {
                vba_keywords.join(", ").chars().take(100).collect()
            },
            severity: sev,
            description: "Document Office avec macros VBA détectées".to_string(),
        });
    }

    Some((
        ArchiveInfo {
            archive_type: archive_type.to_string(),
            total_entries,
            entries,
            has_nested_executable,
            has_double_extension,
            has_encrypted_entries,
            has_vba_macros,
            vba_keywords,
        },
        ioc_list,
    ))
}
