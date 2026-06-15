/// mime.rs — Détection MIME par magic bytes (bytes-based via `infer`)
/// + catégorisation étendue : PE, ELF, Mach-O, scripts (Windows + Unix),
/// archives, Office, PDF, LNK.

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileCategory {
    Pe,
    Elf,
    MachO,
    Script,
    Archive,
    OfficeDoc,
    Pdf,
    Lnk,
    Document,
    Other,
}

impl FileCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileCategory::Pe => "Exécutable Windows (PE)",
            FileCategory::Elf => "Exécutable Linux (ELF)",
            FileCategory::MachO => "Exécutable macOS (Mach-O)",
            FileCategory::Script => "Script",
            FileCategory::Archive => "Archive",
            FileCategory::OfficeDoc => "Document Office",
            FileCategory::Pdf => "PDF",
            FileCategory::Lnk => "Raccourci Windows",
            FileCategory::Document => "Document",
            FileCategory::Other => "Autre",
        }
    }
}

/// Détecte le type MIME réel à partir des bytes.
pub fn detect(data: &[u8], file_name: &str) -> String {
    if let Some(kind) = infer::get(data) {
        return kind.mime_type().to_string();
    }
    // Fallbacks magic bytes non couverts par infer
    if data.starts_with(b"MZ") {
        return "application/x-dosexec".to_string();
    }
    if data.starts_with(&[0x7F, b'E', b'L', b'F']) {
        return "application/x-executable".to_string();
    }
    if data.starts_with(b"%PDF") {
        return "application/pdf".to_string();
    }
    if data.starts_with(&[0x4C, 0x00, 0x00, 0x00]) && file_name.to_lowercase().ends_with(".lnk") {
        return "application/x-ms-shortcut".to_string();
    }
    if std::str::from_utf8(&data[..data.len().min(1024)]).is_ok() {
        return "text/plain".to_string();
    }
    "application/octet-stream".to_string()
}

const SCRIPT_EXTENSIONS: &[&str] = &[
    // Windows
    "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
    // Unix / cross-platform
    "sh", "bash", "zsh", "py", "pyw", "pl", "php", "rb", "lua",
];

const OFFICE_EXTENSIONS: &[&str] = &[
    "docx", "docm", "dotm", "xlsx", "xlsm", "xltm", "pptx", "pptm", "doc", "xls", "ppt",
];

/// Catégorise à partir du MIME, des magic bytes et de l'extension.
pub fn categorize(mime: &str, data: &[u8], file_name: &str) -> FileCategory {
    let ext = file_name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_lowercase();

    // Magic bytes prioritaires (le MIME peut être générique)
    if data.starts_with(b"MZ") || mime == "application/x-dosexec" || mime == "application/vnd.microsoft.portable-executable" {
        return FileCategory::Pe;
    }
    if data.starts_with(&[0x7F, b'E', b'L', b'F']) {
        return FileCategory::Elf;
    }
    // Mach-O : FE ED FA CE / CF (32/64 BE), CE/CF FA ED FE (LE), CA FE BA BE (fat)
    if data.len() >= 4 {
        let magic = &data[..4];
        if magic == [0xFE, 0xED, 0xFA, 0xCE]
            || magic == [0xFE, 0xED, 0xFA, 0xCF]
            || magic == [0xCE, 0xFA, 0xED, 0xFE]
            || magic == [0xCF, 0xFA, 0xED, 0xFE]
            || magic == [0xCA, 0xFE, 0xBA, 0xBE]
        {
            return FileCategory::MachO;
        }
    }
    if data.starts_with(b"%PDF") || mime.contains("pdf") {
        return FileCategory::Pdf;
    }
    if data.starts_with(&[0x4C, 0x00, 0x00, 0x00]) && ext == "lnk" {
        return FileCategory::Lnk;
    }
    // Office OOXML (= ZIP) avant la catégorie Archive générique.
    // Vérification anti-spoofing : un vrai fichier OOXML est un ZIP (magic PK\x03\x04).
    if OFFICE_EXTENSIONS.contains(&ext.as_str()) {
        if data.starts_with(b"PK\x03\x04") {
            return FileCategory::OfficeDoc;
        }
        // Extension Office mais pas un ZIP → traiter comme binaire ou autre selon magic
        // (la suite du match appliquera la catégorie correcte)
    }
    // Script : vérifier que les magic bytes ne trahissent pas un exécutable déguisé.
    if SCRIPT_EXTENSIONS.contains(&ext.as_str()) {
        let is_binary = infer::get(data)
            .map(|k| {
                let m = k.mime_type();
                m == "application/x-dosexec"
                    || m == "application/x-executable"
                    || m == "application/x-mach-binary"
                    || m == "application/vnd.microsoft.portable-executable"
            })
            .unwrap_or(false)
            || data.starts_with(b"MZ")
            || data.starts_with(&[0x7F, b'E', b'L', b'F']);
        if !is_binary {
            return FileCategory::Script;
        }
        // Tombe en cascade vers PE/ELF déjà couverts ci-dessus (ou Other)
    }
    // Shebang → script même sans extension
    if data.starts_with(b"#!") {
        return FileCategory::Script;
    }
    if mime.contains("zip")
        || mime.contains("rar")
        || mime.contains("7z")
        || mime.contains("tar")
        || mime.contains("gzip")
        || mime.contains("bzip2")
        || mime.contains("xz")
        || matches!(ext.as_str(), "zip" | "jar" | "apk" | "rar" | "7z" | "tar" | "gz" | "iso")
    {
        return FileCategory::Archive;
    }
    if mime.contains("word") || mime.contains("excel") || mime.contains("office") {
        return FileCategory::Document;
    }
    FileCategory::Other
}
