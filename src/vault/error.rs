#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("API error: {0}")]
    Api(String),

    #[error("API error: {0}")]
    ApiError(String),

    #[error("Parsing error: {0}")]
    Parsing(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("HTTP status {0}: {1}")]
    HttpStatus(u16, String),

    #[error("Vault is sealed: {0}")]
    Sealed(String),

    #[error("Vault is already initialized")]
    AlreadyInitialized,

    #[error("Request error: {0}")]
    RequestError(String),

    #[error("Error from reqwest: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
