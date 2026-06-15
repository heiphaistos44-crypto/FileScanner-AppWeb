/// binary_parser.rs — Analyse unifiée PE + ELF + Mach-O via goblin.
/// Étend le pe_parser.rs du desktop aux binaires Linux et macOS.
use goblin::Object;

use crate::analyzer::entropy::shannon_entropy;
use crate::error::ScanError;
use crate::types::{BinaryInfo, BinarySection, IoC, Severity};

const SUSPICIOUS_PE_IMPORTS: &[&str] = &[
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetWindowsHookEx",
    "GetAsyncKeyState", "CryptEncrypt", "CryptDecrypt", "InternetOpen",
    "InternetConnect", "URLDownloadToFile", "ShellExecute", "WinExec",
    "CreateProcess", "OpenProcess", "ReadProcessMemory", "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    // Étendus
    "QueueUserAPC", "RtlCreateUserThread", "AdjustTokenPrivileges",
    "CryptAcquireContext", "GetClipboardData", "BitBlt", "RegSetValue",
];

const SUSPICIOUS_ELF_IMPORTS: &[&str] = &[
    "ptrace", "execve", "fork", "dlopen", "mprotect", "memfd_create",
    "setuid", "setgid", "chroot", "socket", "connect", "system", "popen",
];

const PACKER_SIGNATURES: &[(&str, &[u8])] = &[
    ("UPX", b"UPX0"),
    ("UPX1", b"UPX1"),
    ("MPRESS", b"MPRESS1"),
    ("PECompact", b"PECompact2"),
    ("Themida", b"Themida"),
    // Étendus
    ("VMProtect", b".vmp0"),
    ("ASPack", b".aspack"),
    ("Petite", b".petite"),
    ("FSG", b"FSG!"),
    ("NsPack", b".nsp0"),
];

pub fn parse(raw_bytes: &[u8]) -> Result<(BinaryInfo, Vec<IoC>), ScanError> {
    let obj = Object::parse(raw_bytes).map_err(|e| ScanError::BinaryParseError(e.to_string()))?;

    match obj {
        Object::PE(pe) => Ok(analyze_pe(raw_bytes, &pe)),
        Object::Elf(elf) => Ok(analyze_elf(raw_bytes, &elf)),
        Object::Mach(mach) => Ok(analyze_macho(raw_bytes, &mach)),
        _ => Err(ScanError::BinaryParseError("Format binaire non reconnu".to_string())),
    }
}

// ─── PE (Windows) ─────────────────────────────────────────────────────────────

fn analyze_pe(raw_bytes: &[u8], pe: &goblin::pe::PE) -> (BinaryInfo, Vec<IoC>) {
    let mut sections = Vec::new();
    let mut entropy_max: f64 = 0.0;

    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name).trim_matches('\0').to_string();
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let end = (start + size).min(raw_bytes.len());
        let section_data = if start < raw_bytes.len() { &raw_bytes[start..end] } else { &[] };

        let entropy = shannon_entropy(section_data);
        entropy_max = entropy_max.max(entropy);

        sections.push(BinarySection {
            name,
            virtual_size: section.virtual_size as u64,
            raw_size: section.size_of_raw_data as u64,
            entropy,
        });
    }

    let imports: Vec<String> = pe.imports.iter().map(|i| i.name.to_string()).collect();
    let suspicious_imports = filter_suspicious(&imports, SUSPICIOUS_PE_IMPORTS);

    let is_packed = detect_packer(raw_bytes).is_some() || entropy_max > 7.2;
    let is_signed = detect_pe_signature(pe);

    let mut ioc_list = build_common_iocs(entropy_max, &suspicious_imports, classify_pe_import);

    if !is_signed {
        ioc_list.push(IoC {
            ioc_type: "Signature".to_string(),
            value: "Non signé".to_string(),
            severity: Severity::Low,
            description: "L'exécutable ne possède pas de signature numérique".to_string(),
        });
    }

    add_packer_iocs(raw_bytes, &mut ioc_list);

    (
        BinaryInfo {
            format: "PE".to_string(),
            is_64bit: pe.is_64,
            is_signed,
            sections,
            imports,
            entry_point: pe.entry as u64,
            entropy_max,
            suspicious_imports,
            is_packed,
        },
        ioc_list,
    )
}

const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;

fn detect_pe_signature(pe: &goblin::pe::PE) -> bool {
    pe.header
        .optional_header
        .map(|oh| {
            oh.data_directories
                .data_directories
                .get(IMAGE_DIRECTORY_ENTRY_SECURITY)
                .and_then(|e| e.as_ref())
                .map(|(_, d)| d.virtual_address != 0)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

fn classify_pe_import(import: &str) -> Severity {
    let critical = &["CreateRemoteThread", "WriteProcessMemory", "NtUnmapViewOfSection",
                     "ZwUnmapViewOfSection", "QueueUserAPC", "RtlCreateUserThread"];
    let high = &["VirtualAllocEx", "SetWindowsHookEx", "URLDownloadToFile", "WinExec",
                 "AdjustTokenPrivileges"];
    let medium = &["CryptEncrypt", "CryptDecrypt", "InternetOpen", "InternetConnect",
                   "ReadProcessMemory", "GetClipboardData"];

    if critical.iter().any(|s| import.contains(s)) {
        Severity::Critical
    } else if high.iter().any(|s| import.contains(s)) {
        Severity::High
    } else if medium.iter().any(|s| import.contains(s)) {
        Severity::Medium
    } else {
        Severity::Low
    }
}

// ─── ELF (Linux) ──────────────────────────────────────────────────────────────

fn analyze_elf(raw_bytes: &[u8], elf: &goblin::elf::Elf) -> (BinaryInfo, Vec<IoC>) {
    let mut sections = Vec::new();
    let mut entropy_max: f64 = 0.0;

    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("?").to_string();
        let start = sh.sh_offset as usize;
        let size = sh.sh_size as usize;
        // saturating_add évite l'overflow sur des offsets malformés
        let end = start.saturating_add(size).min(raw_bytes.len());
        let data = if start < raw_bytes.len() && sh.sh_type != goblin::elf::section_header::SHT_NOBITS {
            &raw_bytes[start..end]
        } else {
            &[]
        };

        let entropy = shannon_entropy(data);
        entropy_max = entropy_max.max(entropy);

        sections.push(BinarySection {
            name,
            virtual_size: sh.sh_size,
            raw_size: size as u64,
            entropy,
        });
    }

    // Imports = symboles dynamiques importés
    let imports: Vec<String> = elf
        .dynsyms
        .iter()
        .filter(|sym| sym.is_import())
        .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name).map(String::from))
        .collect();

    let suspicious_imports = filter_suspicious(&imports, SUSPICIOUS_ELF_IMPORTS);
    let is_packed = detect_packer(raw_bytes).is_some() || entropy_max > 7.2;

    let mut ioc_list = build_common_iocs(entropy_max, &suspicious_imports, classify_elf_import);

    // Binaire statique strippé = courant pour le malware Linux
    if elf.dynsyms.is_empty() && elf.syms.is_empty() {
        ioc_list.push(IoC {
            ioc_type: "ELF".to_string(),
            value: "Binaire strippé".to_string(),
            severity: Severity::Low,
            description: "Aucun symbole — binaire strippé (fréquent pour malware Linux)".to_string(),
        });
    }

    add_packer_iocs(raw_bytes, &mut ioc_list);

    (
        BinaryInfo {
            format: "ELF".to_string(),
            is_64bit: elf.is_64,
            is_signed: false, // pas de signature native ELF
            sections,
            imports,
            entry_point: elf.entry,
            entropy_max,
            suspicious_imports,
            is_packed,
        },
        ioc_list,
    )
}

fn classify_elf_import(import: &str) -> Severity {
    let critical = &["ptrace", "memfd_create"];
    let high = &["mprotect", "dlopen", "setuid", "chroot"];
    let medium = &["execve", "fork", "system", "popen", "socket", "connect"];

    if critical.iter().any(|s| import.contains(s)) {
        Severity::Critical
    } else if high.iter().any(|s| import.contains(s)) {
        Severity::High
    } else if medium.iter().any(|s| import.contains(s)) {
        Severity::Medium
    } else {
        Severity::Low
    }
}

// ─── Mach-O (macOS) ───────────────────────────────────────────────────────────

fn analyze_macho(raw_bytes: &[u8], mach: &goblin::mach::Mach) -> (BinaryInfo, Vec<IoC>) {
    use goblin::mach::Mach;

    let binary = match mach {
        Mach::Binary(b) => b,
        Mach::Fat(fat) => {
            // Multi-arch : analyse la première architecture
            match fat.get(0) {
                Ok(goblin::mach::SingleArch::MachO(b)) => {
                    return analyze_macho_binary(raw_bytes, &b);
                }
                _ => {
                    return (
                        BinaryInfo {
                            format: "Mach-O (fat)".to_string(),
                            is_64bit: false,
                            is_signed: false,
                            sections: vec![],
                            imports: vec![],
                            entry_point: 0,
                            entropy_max: shannon_entropy(raw_bytes),
                            suspicious_imports: vec![],
                            is_packed: false,
                        },
                        vec![],
                    );
                }
            }
        }
    };
    analyze_macho_binary(raw_bytes, binary)
}

fn analyze_macho_binary(
    raw_bytes: &[u8],
    macho: &goblin::mach::MachO,
) -> (BinaryInfo, Vec<IoC>) {
    let mut sections = Vec::new();
    let mut entropy_max: f64 = 0.0;

    for segment in &macho.segments {
        let name = segment.name().unwrap_or("?").to_string();
        let start = segment.fileoff as usize;
        let size = segment.filesize as usize;
        // saturating_add évite l'overflow sur des offsets Mach-O malformés
        let end = start.saturating_add(size).min(raw_bytes.len());
        let data = if start < raw_bytes.len() { &raw_bytes[start..end] } else { &[] };

        let entropy = shannon_entropy(data);
        entropy_max = entropy_max.max(entropy);

        sections.push(BinarySection {
            name,
            virtual_size: segment.vmsize,
            raw_size: segment.filesize,
            entropy,
        });
    }

    let imports: Vec<String> = macho
        .imports()
        .map(|imps| imps.iter().map(|i| i.name.to_string()).collect())
        .unwrap_or_default();

    let suspicious_imports = filter_suspicious(&imports, SUSPICIOUS_ELF_IMPORTS);
    let is_packed = entropy_max > 7.2;

    let ioc_list = build_common_iocs(entropy_max, &suspicious_imports, classify_elf_import);

    (
        BinaryInfo {
            format: "Mach-O".to_string(),
            is_64bit: macho.is_64,
            is_signed: false,
            sections,
            imports,
            entry_point: macho.entry,
            entropy_max,
            suspicious_imports,
            is_packed,
        },
        ioc_list,
    )
}

// ─── Helpers communs ──────────────────────────────────────────────────────────

fn filter_suspicious(imports: &[String], suspicious: &[&str]) -> Vec<String> {
    imports
        .iter()
        .filter(|name| {
            suspicious
                .iter()
                .any(|s| name.to_lowercase().contains(&s.to_lowercase()))
        })
        .cloned()
        .collect()
}

fn detect_packer(data: &[u8]) -> Option<&'static str> {
    PACKER_SIGNATURES
        .iter()
        .find(|(_, sig)| data.windows(sig.len()).any(|w| w == *sig))
        .map(|(name, _)| *name)
}

fn add_packer_iocs(raw_bytes: &[u8], ioc_list: &mut Vec<IoC>) {
    for (name, sig) in PACKER_SIGNATURES {
        if raw_bytes.windows(sig.len()).any(|w| w == *sig) {
            ioc_list.push(IoC {
                ioc_type: "Packer".to_string(),
                value: name.to_string(),
                severity: Severity::Medium,
                description: format!("Signature du packer {} détectée", name),
            });
        }
    }
}

fn build_common_iocs(
    entropy_max: f64,
    suspicious_imports: &[String],
    classify: fn(&str) -> Severity,
) -> Vec<IoC> {
    let mut ioc_list = Vec::new();

    if entropy_max > 7.2 {
        ioc_list.push(IoC {
            ioc_type: "Entropie".to_string(),
            value: format!("{:.2}", entropy_max),
            severity: if entropy_max > 7.5 { Severity::High } else { Severity::Medium },
            description: "Entropie élevée — possible packer ou chiffrement".to_string(),
        });
    }

    for import in suspicious_imports {
        ioc_list.push(IoC {
            ioc_type: "Import suspect".to_string(),
            value: import.clone(),
            severity: classify(import),
            description: format!("Fonction API sensible : {}", import),
        });
    }

    ioc_list
}
