use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("Erreur E/S : {0}")]
    Io(#[from] std::io::Error),

    #[error("Analyse binaire échouée : {0}")]
    BinaryParseError(String),

    #[error("Erreur HTTP : {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Quota VirusTotal dépassé")]
    RateLimited,

    #[error("{0}")]
    Internal(String),
}
