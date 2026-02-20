use crate::config::{AuthorizerConfig, RealmConfig};
use crate::error::{ESTError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct Principal {
    pub username: String,
    pub roles: Vec<String>,
}

/// Realm provides authentication
pub trait Realm: Send + Sync {
    fn authenticate(&self, username: &str, password: &str) -> Result<Principal>;
}

/// In-memory realm implementation
pub struct InMemoryRealm {
    username: String,
    password: String,
    roles: Vec<String>,
}

impl InMemoryRealm {
    pub fn new(config: RealmConfig) -> Result<Self> {
        match config {
            RealmConfig::InMemory { username, password, roles } => {
                Ok(Self { username, password, roles })
            }
        }
    }
}

impl Realm for InMemoryRealm {
    fn authenticate(&self, username: &str, password: &str) -> Result<Principal> {
        if username == self.username && password == self.password {
            Ok(Principal {
                username: username.to_string(),
                roles: self.roles.clone(),
            })
        } else {
            Err(ESTError::AuthenticationFailed("Invalid credentials".to_string()))
        }
    }
}

/// Authorization context passed to authorizers
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationContext {
    #[serde(rename = "authzData")]
    pub authz_data: AuthzData,
    pub operation: String,
    #[serde(rename = "remoteAddr")]
    pub remote_addr: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthzData {
    pub principal: PrincipalData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PrincipalData {
    pub name: String,
    pub roles: Vec<String>,
}

/// Request authorizer
#[async_trait]
pub trait RequestAuthorizer: Send + Sync {
    async fn authorize(&self, context: &AuthorizationContext) -> Result<()>;
}

/// External process authorizer
pub struct ExternalProcessAuthorizer {
    executable: std::path::PathBuf,
}

impl ExternalProcessAuthorizer {
    pub fn new(config: AuthorizerConfig) -> Result<Self> {
        match config {
            AuthorizerConfig::ExternalProcess { executable } => {
                if !executable.exists() {
                    return Err(ESTError::Config(format!(
                        "Authorizer executable not found: {}",
                        executable.display()
                    )));
                }
                Ok(Self { executable })
            }
            AuthorizerConfig::AllowAll => {
                Err(ESTError::Config("Wrong authorizer type".to_string()))
            }
        }
    }
}

#[async_trait]
impl RequestAuthorizer for ExternalProcessAuthorizer {
    async fn authorize(&self, context: &AuthorizationContext) -> Result<()> {
        let json = serde_json::to_string(context)
            .map_err(|e| ESTError::Internal(format!("Failed to serialize context: {}", e)))?;

        let mut child = Command::new(&self.executable)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| ESTError::Internal(format!("Failed to spawn authorizer: {}", e)))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(json.as_bytes()).await
                .map_err(|e| ESTError::Internal(format!("Failed to write to authorizer: {}", e)))?;
        }

        let output = child.wait_with_output().await
            .map_err(|e| ESTError::Internal(format!("Failed to wait for authorizer: {}", e)))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let message = if !stderr.is_empty() {
                stderr.to_string()
            } else if !stdout.is_empty() {
                stdout.to_string()
            } else {
                "Authorization failed".to_string()
            };
            Err(ESTError::AuthorizationFailed(message))
        }
    }
}

/// Allow-all authorizer (for testing)
pub struct AllowAllAuthorizer;

impl AllowAllAuthorizer {
    pub fn new(_config: AuthorizerConfig) -> Result<Self> {
        Ok(Self)
    }
}

#[async_trait]
impl RequestAuthorizer for AllowAllAuthorizer {
    async fn authorize(&self, _context: &AuthorizationContext) -> Result<()> {
        Ok(())
    }
}

/// Create authorizer from configuration
pub fn create_authorizer(config: AuthorizerConfig) -> Result<Box<dyn RequestAuthorizer>> {
    match &config {
        AuthorizerConfig::ExternalProcess { .. } => {
            Ok(Box::new(ExternalProcessAuthorizer::new(config)?))
        }
        AuthorizerConfig::AllowAll => Ok(Box::new(AllowAllAuthorizer::new(config)?)),
    }
}
