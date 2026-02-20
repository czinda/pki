mod auth;
mod backend;
mod config;
mod error;
mod handlers;

use crate::auth::{create_authorizer, InMemoryRealm, Realm};
use crate::config::{AuthorizerConfig, BackendConfig, RealmConfig, ServerConfig};
use crate::handlers::{
    AppState, AuthenticatedPrincipal, get_ca_certs, get_ca_certs_with_label,
    simple_enroll, simple_reenroll,
    simple_enroll_labeled, simple_reenroll_labeled,
};
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use base64::Engine;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pki_est=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let config_path = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from("/etc/pki/pki-tomcat/conf/est/server.conf")
    };

    // Load configuration
    tracing::info!("Loading configuration from {}", config_path.display());
    let server_config = ServerConfig::from_file(&config_path)?;

    // Load backend configuration
    let backend_config = BackendConfig::from_file(&server_config.backend_config)?;
    let backend = backend::create_backend(backend_config)?;
    tracing::info!("Backend initialized");

    // Load authorizer configuration
    let authorizer_config = AuthorizerConfig::from_file(&server_config.authorizer_config)?;
    let authorizer = create_authorizer(authorizer_config)?;
    tracing::info!("Authorizer initialized");

    // Load realm configuration
    let realm_config = RealmConfig::from_file(&server_config.realm_config)?;
    let realm = Arc::new(InMemoryRealm::new(realm_config)?);
    tracing::info!("Realm initialized");

    // Create application state
    let app_state = Arc::new(AppState {
        backend,
        authorizer,
    });

    // Build router
    let app = Router::new()
        // EST endpoints without label
        .route("/.well-known/est/cacerts", get(get_ca_certs))
        .route("/.well-known/est/simpleenroll", post(simple_enroll))
        .route("/.well-known/est/simplereenroll", post(simple_reenroll))
        // EST endpoints with label
        .route("/.well-known/est/:label/cacerts", get(get_ca_certs_with_label))
        .route("/.well-known/est/:label/simpleenroll", post(simple_enroll_labeled))
        .route("/.well-known/est/:label/simplereenroll", post(simple_reenroll_labeled))
        .layer(middleware::from_fn_with_state(
            realm.clone(),
            basic_auth_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    // Bind server
    let bind_addr = format!("{}:{}", server_config.bind_addr, server_config.port);
    tracing::info!("Starting EST server on {}", bind_addr);

    let listener = TcpListener::bind(&bind_addr).await?;

    // For this PoC, we'll use plain HTTP
    // In production, TLS should be added using rustls-tls:
    //
    // use tokio_rustls::TlsAcceptor;
    // let certs = load_certs(&server_config.tls_cert)?;
    // let key = load_private_key(&server_config.tls_key)?;
    // let tls_config = ServerConfig::builder()
    //     .with_no_client_auth()
    //     .with_single_cert(certs, key)?;
    // let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    //
    // Then wrap each incoming connection with:
    // let tls_stream = acceptor.accept(tcp_stream).await?;

    tracing::info!("EST server running on http://{}", bind_addr);
    tracing::warn!("WARNING: Running without TLS for PoC purposes only!");
    tracing::info!("In production, TLS must be enabled - see NEXT-STEPS.md");

    axum::serve(listener, app).await?;

    Ok(())
}

/// Basic authentication middleware
async fn basic_auth_middleware(
    axum::extract::State(realm): axum::extract::State<Arc<InMemoryRealm>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    if let Some(auth_value) = auth_header {
        if let Some(credentials) = auth_value.strip_prefix("Basic ") {
            // Decode base64 credentials
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(credentials) {
                if let Ok(creds_str) = String::from_utf8(decoded) {
                    if let Some((username, password)) = creds_str.split_once(':') {
                        // Authenticate
                        match realm.authenticate(username, password) {
                            Ok(principal) => {
                                // Insert principal into request extensions
                                request.extensions_mut().insert(AuthenticatedPrincipal(principal));
                                return next.run(request).await;
                            }
                            Err(e) => {
                                tracing::warn!("Authentication failed: {}", e);
                            }
                        }
                    }
                }
            }
        }
    }

    // For /cacerts endpoint, authentication is optional
    if request.uri().path().ends_with("/cacerts") {
        return next.run(request).await;
    }

    // Authentication required for other endpoints
    (
        StatusCode::UNAUTHORIZED,
        [("WWW-Authenticate", "Basic realm=\"EST\"")],
        "Authentication required",
    )
        .into_response()
}
