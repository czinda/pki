use crate::auth::{AuthorizationContext, AuthzData, Principal, PrincipalData, RequestAuthorizer};
use crate::backend::{CertRequest, ESTBackend};
use crate::error::{ESTError, Result};
use axum::{
    async_trait,
    body::Bytes,
    extract::{FromRequestParts, Path, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::sync::Arc;

/// Application state shared across handlers
pub struct AppState {
    pub backend: Box<dyn ESTBackend>,
    pub authorizer: Box<dyn RequestAuthorizer>,
}

/// Extension type for authenticated principal
#[derive(Clone)]
pub struct AuthenticatedPrincipal(pub Principal);

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedPrincipal
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> std::result::Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthenticatedPrincipal>()
            .cloned()
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "Authentication required",
            ))
    }
}

/// GET /.well-known/est/cacerts
/// Returns the CA certificate chain in PKCS#7 format
pub async fn get_ca_certs(
    State(state): State<Arc<AppState>>,
    principal: Option<AuthenticatedPrincipal>,
) -> Result<Response> {
    tracing::info!("Handling /cacerts request");

    // Authorization check (optional for cacerts in some deployments)
    if let Some(AuthenticatedPrincipal(principal)) = principal {
        let ctx = AuthorizationContext {
            authz_data: AuthzData {
                principal: PrincipalData {
                    name: principal.username.clone(),
                    roles: principal.roles.clone(),
                },
            },
            operation: "cacerts".to_string(),
            remote_addr: "unknown".to_string(), // TODO: Extract from request
        };

        state.authorizer.authorize(&ctx).await?;
    }

    // Fetch CA certificates from backend
    let ca_certs = state.backend.get_ca_certs(None).await?;

    // Return PKCS#7 encoded certificates
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/pkcs7-mime")],
        BASE64.encode(&ca_certs),
    )
        .into_response())
}

/// GET /.well-known/est/:label/cacerts
/// Returns the CA certificate chain for a specific label
pub async fn get_ca_certs_with_label(
    State(state): State<Arc<AppState>>,
    Path(label): Path<String>,
    principal: Option<AuthenticatedPrincipal>,
) -> Result<Response> {
    tracing::info!("Handling /cacerts request with label: {}", label);

    // Authorization check
    if let Some(AuthenticatedPrincipal(principal)) = principal {
        let ctx = AuthorizationContext {
            authz_data: AuthzData {
                principal: PrincipalData {
                    name: principal.username.clone(),
                    roles: principal.roles.clone(),
                },
            },
            operation: "cacerts".to_string(),
            remote_addr: "unknown".to_string(),
        };

        state.authorizer.authorize(&ctx).await?;
    }

    // Fetch CA certificates with label
    let ca_certs = state.backend.get_ca_certs(Some(&label)).await?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/pkcs7-mime")],
        BASE64.encode(&ca_certs),
    )
        .into_response())
}

/// POST /.well-known/est/simpleenroll
/// Enrolls a new certificate
pub async fn simple_enroll(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    body: Bytes,
) -> Result<Response> {
    simple_enroll_impl(state, principal, body).await
}

/// POST /.well-known/est/simplereenroll
/// Re-enrolls (renews) an existing certificate
pub async fn simple_reenroll(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    body: Bytes,
) -> Result<Response> {
    simple_reenroll_impl(state, principal, body).await
}

/// POST /.well-known/est/:label/simpleenroll
/// Enrolls a new certificate (with label)
pub async fn simple_enroll_labeled(
    State(state): State<Arc<AppState>>,
    Path(_label): Path<String>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    body: Bytes,
) -> Result<Response> {
    // For now, ignore the label and use the same logic as simple_enroll
    // In production, the label would be passed to the backend
    simple_enroll_impl(state, principal, body).await
}

/// POST /.well-known/est/:label/simplereenroll
/// Re-enrolls a certificate (with label)
pub async fn simple_reenroll_labeled(
    State(state): State<Arc<AppState>>,
    Path(_label): Path<String>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    body: Bytes,
) -> Result<Response> {
    // For now, ignore the label and use the same logic as simple_reenroll
    simple_reenroll_impl(state, principal, body).await
}

// Helper function for simple enrollment
async fn simple_enroll_impl(
    state: Arc<AppState>,
    principal: Principal,
    body: Bytes,
) -> Result<Response> {
    tracing::info!("Handling /simpleenroll request for user: {}", principal.username);

    // Authorization check
    let ctx = AuthorizationContext {
        authz_data: AuthzData {
            principal: PrincipalData {
                name: principal.username.clone(),
                roles: principal.roles.clone(),
            },
        },
        operation: "simpleenroll".to_string(),
        remote_addr: "unknown".to_string(),
    };

    state.authorizer.authorize(&ctx).await?;

    // Decode base64 CSR
    let csr_der = BASE64
        .decode(&body)
        .map_err(|e| ESTError::InvalidRequest(format!("Invalid base64 encoding: {}", e)))?;

    // Convert to PEM format for backend
    let csr_pem = pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", csr_der));

    let request = CertRequest { csr_pem };

    // Submit to backend
    let response = state.backend.simple_enroll(&request).await?;

    // Parse certificate and return as base64-encoded DER
    let pem_data = pem::parse(&response.cert_pem)
        .map_err(|e| ESTError::Backend(format!("Failed to parse certificate PEM: {}", e)))?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/pkcs7-mime")],
        BASE64.encode(&pem_data.contents()),
    )
        .into_response())
}

// Helper function for simple re-enrollment
async fn simple_reenroll_impl(
    state: Arc<AppState>,
    principal: Principal,
    body: Bytes,
) -> Result<Response> {
    tracing::info!("Handling /simplereenroll request for user: {}", principal.username);

    // Authorization check
    let ctx = AuthorizationContext {
        authz_data: AuthzData {
            principal: PrincipalData {
                name: principal.username.clone(),
                roles: principal.roles.clone(),
            },
        },
        operation: "simplereenroll".to_string(),
        remote_addr: "unknown".to_string(),
    };

    state.authorizer.authorize(&ctx).await?;

    // Decode base64 CSR
    let csr_der = BASE64
        .decode(&body)
        .map_err(|e| ESTError::InvalidRequest(format!("Invalid base64 encoding: {}", e)))?;

    // Convert to PEM format
    let csr_pem = pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", csr_der));

    let request = CertRequest { csr_pem };

    // TODO: Extract current certificate from TLS client cert
    let current_cert = vec![];

    // Submit to backend
    let response = state.backend.simple_reenroll(&request, &current_cert).await?;

    // Parse certificate and return as base64-encoded DER
    let pem_data = pem::parse(&response.cert_pem)
        .map_err(|e| ESTError::Backend(format!("Failed to parse certificate PEM: {}", e)))?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/pkcs7-mime")],
        BASE64.encode(&pem_data.contents()),
    )
        .into_response())
}
