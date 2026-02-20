use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[derive(Debug, thiserror::Error)]
pub enum ESTError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Authorization failed: {0}")]
    AuthorizationFailed(String),

    #[error("Invalid certificate request: {0}")]
    InvalidRequest(String),

    #[error("Backend error: {0}")]
    Backend(String),

    #[error("Certificate validation failed: {0}")]
    ValidationFailed(String),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("X.509 parsing error: {0}")]
    X509Parse(String),
}

pub type Result<T> = std::result::Result<T, ESTError>;

impl IntoResponse for ESTError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ESTError::AuthenticationFailed(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            ESTError::AuthorizationFailed(_) => (StatusCode::FORBIDDEN, self.to_string()),
            ESTError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            ESTError::ValidationFailed(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()),
        };

        tracing::error!("EST error: {}", self);
        (status, message).into_response()
    }
}
