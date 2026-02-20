use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::error::{ESTError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server bind address
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    /// Server port
    #[serde(default = "default_port")]
    pub port: u16,

    /// TLS certificate path
    pub tls_cert: PathBuf,

    /// TLS private key path
    pub tls_key: PathBuf,

    /// Backend configuration file
    pub backend_config: PathBuf,

    /// Authorizer configuration file
    pub authorizer_config: PathBuf,

    /// Realm (authentication) configuration file
    pub realm_config: PathBuf,
}

fn default_bind_addr() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8443
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "class")]
pub enum BackendConfig {
    #[serde(rename = "org.dogtagpki.est.DogtagRABackend")]
    DogtagRA {
        /// CA URL
        url: String,
        /// CA profile to use
        profile: String,
        /// RA username
        username: Option<String>,
        /// RA password
        password: Option<String>,
        /// CA label (optional)
        label: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "class")]
pub enum AuthorizerConfig {
    #[serde(rename = "org.dogtagpki.est.ExternalProcessRequestAuthorizer")]
    ExternalProcess {
        /// Path to authorization executable
        executable: PathBuf,
    },
    #[serde(rename = "org.dogtagpki.est.AllowAllRequestAuthorizer")]
    AllowAll,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "class")]
pub enum RealmConfig {
    #[serde(rename = "com.netscape.cms.realm.PKIInMemoryRealm")]
    InMemory {
        username: String,
        password: String,
        #[serde(default)]
        roles: Vec<String>,
    },
}

impl ServerConfig {
    pub fn from_file(path: &PathBuf) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ESTError::Config(format!("Failed to read config file: {}", e)))?;

        toml::from_str(&contents)
            .map_err(|e| ESTError::Config(format!("Failed to parse config: {}", e)))
    }
}

impl BackendConfig {
    pub fn from_file(path: &PathBuf) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ESTError::Config(format!("Failed to read backend config: {}", e)))?;

        // Parse as key=value format (Java properties style)
        Self::from_properties(&contents)
    }

    fn from_properties(contents: &str) -> Result<Self> {
        let mut props = std::collections::HashMap::new();

        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                props.insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        let class = props.get("class")
            .ok_or_else(|| ESTError::Config("Missing 'class' in backend config".to_string()))?;

        match class.as_str() {
            "org.dogtagpki.est.DogtagRABackend" => Ok(BackendConfig::DogtagRA {
                url: props.get("url")
                    .ok_or_else(|| ESTError::Config("Missing 'url' in backend config".to_string()))?
                    .to_string(),
                profile: props.get("profile")
                    .ok_or_else(|| ESTError::Config("Missing 'profile' in backend config".to_string()))?
                    .to_string(),
                username: props.get("username").cloned(),
                password: props.get("password").cloned(),
                label: props.get("label").cloned(),
            }),
            _ => Err(ESTError::Config(format!("Unknown backend class: {}", class))),
        }
    }
}

impl AuthorizerConfig {
    pub fn from_file(path: &PathBuf) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ESTError::Config(format!("Failed to read authorizer config: {}", e)))?;

        Self::from_properties(&contents)
    }

    fn from_properties(contents: &str) -> Result<Self> {
        let mut props = std::collections::HashMap::new();

        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                props.insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        let class = props.get("class")
            .ok_or_else(|| ESTError::Config("Missing 'class' in authorizer config".to_string()))?;

        match class.as_str() {
            "org.dogtagpki.est.ExternalProcessRequestAuthorizer" => {
                Ok(AuthorizerConfig::ExternalProcess {
                    executable: PathBuf::from(props.get("executable")
                        .ok_or_else(|| ESTError::Config("Missing 'executable' in authorizer config".to_string()))?),
                })
            }
            "org.dogtagpki.est.AllowAllRequestAuthorizer" => Ok(AuthorizerConfig::AllowAll),
            _ => Err(ESTError::Config(format!("Unknown authorizer class: {}", class))),
        }
    }
}

impl RealmConfig {
    pub fn from_file(path: &PathBuf) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ESTError::Config(format!("Failed to read realm config: {}", e)))?;

        Self::from_properties(&contents)
    }

    fn from_properties(contents: &str) -> Result<Self> {
        let mut props = std::collections::HashMap::new();

        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                props.insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        let class = props.get("class")
            .ok_or_else(|| ESTError::Config("Missing 'class' in realm config".to_string()))?;

        match class.as_str() {
            "com.netscape.cms.realm.PKIInMemoryRealm" => Ok(RealmConfig::InMemory {
                username: props.get("username")
                    .ok_or_else(|| ESTError::Config("Missing 'username' in realm config".to_string()))?
                    .to_string(),
                password: props.get("password")
                    .ok_or_else(|| ESTError::Config("Missing 'password' in realm config".to_string()))?
                    .to_string(),
                roles: props.get("roles")
                    .map(|r| r.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default(),
            }),
            _ => Err(ESTError::Config(format!("Unknown realm class: {}", class))),
        }
    }
}
