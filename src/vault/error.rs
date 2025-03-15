#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("API error: {0}")]
    Api(String),

    #[error("Parsing error: {0}")]
    Parsing(String),

    #[error("Vault is sealed: {0}")]
    Sealed(String),

    #[error("Vault is already initialized")]
    AlreadyInitialized,
    // ...existing code...
}
