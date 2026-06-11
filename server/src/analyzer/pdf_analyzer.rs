/// pdf_analyzer.rs — Détection de menaces PDF (NOUVEAU).
/// /JavaScript, /JS, /OpenAction, /Launch, /EmbeddedFile, /AA, /AcroForm.
use crate::types::{IoC, PdfInfo, Severity};

fn contains(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|w| w == needle)
}

pub fn analyze(data: &[u8]) -> (PdfInfo, Vec<IoC>) {
    let has_javascript = contains(data, b"/JavaScript") || contains(data, b"/JS");
    let has_open_action = contains(data, b"/OpenAction") || contains(data, b"/AA");
    let has_launch_action = contains(data, b"/Launch");
    let has_embedded_files = contains(data, b"/EmbeddedFile") || contains(data, b"/Filespec");
    let has_acroform = contains(data, b"/AcroForm") && contains(data, b"/XFA");

    let mut ioc_list = Vec::new();
    let mut suspicious_count = 0;

    if has_javascript {
        suspicious_count += 1;
        ioc_list.push(IoC {
            ioc_type: "PDF".to_string(),
            value: "/JavaScript".to_string(),
            severity: Severity::High,
            description: "Code JavaScript embarqué dans le PDF".to_string(),
        });
    }
    if has_open_action {
        suspicious_count += 1;
        ioc_list.push(IoC {
            ioc_type: "PDF".to_string(),
            value: "/OpenAction".to_string(),
            severity: if has_javascript { Severity::Critical } else { Severity::Medium },
            description: "Action automatique à l'ouverture du document".to_string(),
        });
    }
    if has_launch_action {
        suspicious_count += 1;
        ioc_list.push(IoC {
            ioc_type: "PDF".to_string(),
            value: "/Launch".to_string(),
            severity: Severity::Critical,
            description: "Lancement d'un programme externe depuis le PDF".to_string(),
        });
    }
    if has_embedded_files {
        suspicious_count += 1;
        ioc_list.push(IoC {
            ioc_type: "PDF".to_string(),
            value: "/EmbeddedFile".to_string(),
            severity: Severity::Medium,
            description: "Fichier(s) embarqué(s) dans le PDF".to_string(),
        });
    }
    if has_acroform {
        suspicious_count += 1;
        ioc_list.push(IoC {
            ioc_type: "PDF".to_string(),
            value: "/AcroForm + /XFA".to_string(),
            severity: Severity::Medium,
            description: "Formulaire XFA — vecteur d'exploit connu".to_string(),
        });
    }

    (
        PdfInfo {
            has_javascript,
            has_open_action,
            has_launch_action,
            has_embedded_files,
            has_acroform,
            suspicious_count,
        },
        ioc_list,
    )
}
