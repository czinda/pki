use crate::config::BackendConfig;
use crate::error::{ESTError, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

/// Certificate signing request
pub struct CertRequest {
    pub csr_pem: String,
}

/// Certificate response
pub struct CertResponse {
    pub cert_pem: String,
}

/// EST Backend trait - defines the interface for CA backends
#[async_trait]
pub trait ESTBackend: Send + Sync {
    /// Get CA certificates
    async fn get_ca_certs(&self, label: Option<&str>) -> Result<Vec<u8>>;

    /// Simple enrollment - issue a certificate from a CSR
    async fn simple_enroll(&self, request: &CertRequest) -> Result<CertResponse>;

    /// Simple re-enrollment - renew a certificate
    async fn simple_reenroll(
        &self,
        request: &CertRequest,
        current_cert: &[u8],
    ) -> Result<CertResponse>;
}

/// Dogtag CA backend implementation
pub struct DogtagRABackend {
    ca_url: String,
    profile: String,
    username: Option<String>,
    password: Option<String>,
    client: reqwest::Client,
}

impl DogtagRABackend {
    pub fn new(config: BackendConfig) -> Result<Self> {
        match config {
            BackendConfig::DogtagRA {
                url,
                profile,
                username,
                password,
                ..
            } => {
                // Build HTTP client with TLS support
                let client = reqwest::Client::builder()
                    .danger_accept_invalid_certs(true) // For self-signed certs in dev
                    .build()
                    .map_err(|e| ESTError::Backend(format!("Failed to create HTTP client: {}", e)))?;

                Ok(Self {
                    ca_url: url,
                    profile,
                    username,
                    password,
                    client,
                })
            }
        }
    }

    fn get_auth_header(&self) -> Option<String> {
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            let credentials = format!("{}:{}", username, password);
            let encoded = BASE64.encode(credentials.as_bytes());
            Some(format!("Basic {}", encoded))
        } else {
            None
        }
    }
}

#[async_trait]
impl ESTBackend for DogtagRABackend {
    async fn get_ca_certs(&self, _label: Option<&str>) -> Result<Vec<u8>> {
        // Fetch CA certificate chain from Dogtag CA
        let url = format!("{}/ca/rest/certs/ca", self.ca_url);

        let mut request = self.client.get(&url);
        if let Some(auth) = self.get_auth_header() {
            request = request.header("Authorization", auth);
        }

        let response = request
            .send()
            .await
            .map_err(|e| ESTError::Backend(format!("Failed to fetch CA certs: {}", e)))?;

        if !response.status().is_success() {
            return Err(ESTError::Backend(format!(
                "CA returned error: {}",
                response.status()
            )));
        }

        let cert_data = response
            .bytes()
            .await
            .map_err(|e| ESTError::Backend(format!("Failed to read CA cert response: {}", e)))?;

        // For EST, we need to return PKCS#7 format
        // This is a simplified implementation - in production, would need proper PKCS#7 encoding
        Ok(cert_data.to_vec())
    }

    async fn simple_enroll(&self, request: &CertRequest) -> Result<CertResponse> {
        // Submit certificate request to Dogtag CA
        let url = format!("{}/ca/rest/certrequests", self.ca_url);

        // Parse CSR to extract subject DN and other info
        // For this PoC, we'll send the CSR directly
        let request_data = serde_json::json!({
            "Attributes": {
                "Attribute": []
            },
            "Input": [{
                "Attribute": [{
                    "name": "cert_request_type",
                    "value": "pkcs10"
                }, {
                    "name": "cert_request",
                    "value": request.csr_pem
                }]
            }],
            "ProfileID": self.profile,
        });

        let mut http_request = self.client.post(&url).json(&request_data);
        if let Some(auth) = self.get_auth_header() {
            http_request = http_request.header("Authorization", auth);
        }

        let response = http_request
            .send()
            .await
            .map_err(|e| ESTError::Backend(format!("Failed to submit cert request: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ESTError::Backend(format!(
                "CA returned error {}: {}",
                status, body
            )));
        }

        let response_json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| ESTError::Backend(format!("Failed to parse CA response: {}", e)))?;

        // Extract certificate from response
        // The response structure depends on the CA API
        let cert_pem = response_json["entries"][0]["certId"]
            .as_str()
            .ok_or_else(|| ESTError::Backend("No certificate in CA response".to_string()))?
            .to_string();

        Ok(CertResponse { cert_pem })
    }

    async fn simple_reenroll(
        &self,
        request: &CertRequest,
        _current_cert: &[u8],
    ) -> Result<CertResponse> {
        // For reenrollment, we need to validate the current certificate
        // and ensure the new CSR matches the old certificate's subject
        // For this PoC, we'll just call simple_enroll
        // In production, add strict validation as in Java implementation

        self.simple_enroll(request).await
    }
}

/// Create backend from configuration
pub fn create_backend(config: BackendConfig) -> Result<Box<dyn ESTBackend>> {
    match config {
        BackendConfig::DogtagRA { .. } => Ok(Box::new(DogtagRABackend::new(config)?)),
    }
}
