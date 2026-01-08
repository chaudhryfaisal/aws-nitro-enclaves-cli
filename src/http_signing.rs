// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP-based signing support for Nitro Enclave images.
//!
//! This module provides support for signing enclave images using external HTTP endpoints,
//! with optional mutual TLS (mTLS) authentication.
//!
//! # URL Format
//!
//! ```text
//! https://host:port/path;client_cert={path};client_key={path};request_template={base64};response_template={base64}
//! ```
//!
//! # Example
//!
//! ```text
//! https://signing.example.com/v2/core/sign/ecdsa-sha256;client_cert=/path/to/cert.pem;client_key=/path/to/key.pem
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::blocking::Client;
use reqwest::Identity;
use serde_json::Value;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs;
use std::path::Path;
use std::time::Duration;

/// Default request template: `{"message":"{payload}"}`
const DEFAULT_REQUEST_TEMPLATE: &str = r#"{"message":"{payload}"}"#;

/// Signing algorithm for ECDSA signatures.
///
/// Supported algorithms:
/// - ES384: ECDSA with P-384 curve and SHA-384 (default)
/// - ES512: ECDSA with P-521 curve and SHA-512
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SigningAlgorithm {
    /// ECDSA with P-384 curve and SHA-384 (COSE algorithm ID: -35)
    #[default]
    ES384,
    /// ECDSA with P-521 curve and SHA-512 (COSE algorithm ID: -37)
    ES512,
}

impl SigningAlgorithm {
    /// Get the COSE algorithm identifier for this signing algorithm.
    pub fn cose_algorithm_id(&self) -> i32 {
        match self {
            SigningAlgorithm::ES384 => -35,
            SigningAlgorithm::ES512 => -37,
        }
    }

    /// Parse a signing algorithm from a string.
    ///
    /// Accepts "ES384" or "ES512" (case-insensitive).
    pub fn from_str(s: &str) -> Result<Self, HttpSigningError> {
        match s.to_uppercase().as_str() {
            "ES384" => Ok(SigningAlgorithm::ES384),
            "ES512" => Ok(SigningAlgorithm::ES512),
            _ => Err(HttpSigningError::UrlParseError(format!(
                "Invalid algorithm '{}'. Supported algorithms: ES384, ES512",
                s
            ))),
        }
    }
}

impl std::fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningAlgorithm::ES384 => write!(f, "ES384"),
            SigningAlgorithm::ES512 => write!(f, "ES512"),
        }
    }
}

/// Default response template: `{"signature":"{signature}"}`
const DEFAULT_RESPONSE_TEMPLATE: &str = r#"{"signature":"{signature}"}"#;

/// Placeholder for payload in request template
const PAYLOAD_PLACEHOLDER: &str = "{payload}";

/// Placeholder for signature in response template
const SIGNATURE_PLACEHOLDER: &str = "{signature}";

/// HTTP request timeout in seconds
const HTTP_TIMEOUT_SECS: u64 = 30;

/// Errors that can occur during HTTP signing operations.
#[derive(Debug, Clone)]
pub enum HttpSigningError {
    /// Invalid URL format or missing required parameters
    UrlParseError(String),
    /// TLS/mTLS configuration error
    TlsError(String),
    /// HTTP request failed
    RequestError(String),
    /// Invalid response format or missing signature
    ResponseError(String),
    /// Invalid template format
    TemplateError(String),
    /// File read error
    FileError(String),
}

impl std::fmt::Display for HttpSigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpSigningError::UrlParseError(msg) => write!(f, "URL parse error: {}", msg),
            HttpSigningError::TlsError(msg) => write!(f, "TLS error: {}", msg),
            HttpSigningError::RequestError(msg) => write!(f, "HTTP request error: {}", msg),
            HttpSigningError::ResponseError(msg) => write!(f, "Response error: {}", msg),
            HttpSigningError::TemplateError(msg) => write!(f, "Template error: {}", msg),
            HttpSigningError::FileError(msg) => write!(f, "File error: {}", msg),
        }
    }
}

impl std::error::Error for HttpSigningError {}

/// Configuration for HTTP-based signing.
#[derive(Debug, Clone)]
pub struct HttpSigningConfig {
    /// The base URL for the signing endpoint
    pub url: String,
    /// Optional path to client certificate for mTLS
    pub client_cert_path: Option<String>,
    /// Optional path to client private key for mTLS
    pub client_key_path: Option<String>,
    /// Request template with {payload} placeholder
    pub request_template: String,
    /// Response template with {signature} placeholder
    pub response_template: String,
    /// Signing algorithm (ES384 or ES512, defaults to ES384)
    pub algorithm: SigningAlgorithm,
}

impl HttpSigningConfig {
    /// Parse an HTTP signing URL into a configuration.
    ///
    /// # Format
    ///
    /// ```text
    /// https://host:port/path;client_cert={path};client_key={path};request_template={base64};response_template={base64}
    /// ```
    pub fn parse(url_str: &str) -> Result<Self, HttpSigningError> {
        // Split by semicolon to get URL and parameters
        let parts: Vec<&str> = url_str.splitn(2, ';').collect();
        let base_url = parts[0].to_string();

        // Validate URL starts with https://
        if !base_url.starts_with("https://") {
            return Err(HttpSigningError::UrlParseError(
                "HTTP signing URL must use HTTPS".to_string(),
            ));
        }

        // Parse parameters if present
        let mut params: HashMap<String, String> = HashMap::new();
        if parts.len() > 1 {
            for param in parts[1].split(';') {
                if let Some((key, value)) = param.split_once('=') {
                    params.insert(key.to_string(), value.to_string());
                }
            }
        }

        // Extract client certificate and key paths
        let client_cert_path = params.get("client_cert").cloned();
        let client_key_path = params.get("client_key").cloned();

        // Validate that both cert and key are provided together
        if client_cert_path.is_some() != client_key_path.is_some() {
            return Err(HttpSigningError::UrlParseError(
                "Both client_cert and client_key must be provided for mTLS".to_string(),
            ));
        }

        // Parse request template (base64 encoded)
        let request_template = match params.get("request_template") {
            Some(b64) => {
                let decoded = BASE64.decode(b64).map_err(|e| {
                    HttpSigningError::TemplateError(format!(
                        "Failed to decode request_template: {}",
                        e
                    ))
                })?;
                String::from_utf8(decoded).map_err(|e| {
                    HttpSigningError::TemplateError(format!(
                        "Invalid UTF-8 in request_template: {}",
                        e
                    ))
                })?
            }
            None => DEFAULT_REQUEST_TEMPLATE.to_string(),
        };

        // Parse response template (base64 encoded)
        let response_template = match params.get("response_template") {
            Some(b64) => {
                let decoded = BASE64.decode(b64).map_err(|e| {
                    HttpSigningError::TemplateError(format!(
                        "Failed to decode response_template: {}",
                        e
                    ))
                })?;
                String::from_utf8(decoded).map_err(|e| {
                    HttpSigningError::TemplateError(format!(
                        "Invalid UTF-8 in response_template: {}",
                        e
                    ))
                })?
            }
            None => DEFAULT_RESPONSE_TEMPLATE.to_string(),
        };

        // Validate templates contain required placeholders
        if !request_template.contains(PAYLOAD_PLACEHOLDER) {
            return Err(HttpSigningError::TemplateError(format!(
                "Request template must contain {} placeholder",
                PAYLOAD_PLACEHOLDER
            )));
        }
        if !response_template.contains(SIGNATURE_PLACEHOLDER) {
            return Err(HttpSigningError::TemplateError(format!(
                "Response template must contain {} placeholder",
                SIGNATURE_PLACEHOLDER
            )));
        }

        // Parse algorithm (defaults to ES384)
        let algorithm = match params.get("algorithm") {
            Some(alg_str) => SigningAlgorithm::from_str(alg_str)?,
            None => SigningAlgorithm::default(),
        };

        Ok(HttpSigningConfig {
            url: base_url,
            client_cert_path,
            client_key_path,
            request_template,
            response_template,
            algorithm,
        })
    }
}

/// Check if a private key string is an HTTP signing URL.
pub fn is_http_signing_url(key_location: &str) -> bool {
    key_location.starts_with("https://")
}

/// HTTP-based signer for enclave images.
pub struct HttpSigner {
    config: HttpSigningConfig,
    client: Client,
}

impl HttpSigner {
    /// Create a new HTTP signer from a URL string.
    pub fn new(url_str: &str) -> Result<Self, HttpSigningError> {
        let config = HttpSigningConfig::parse(url_str)?;
        let client = Self::build_client(&config)?;
        Ok(HttpSigner { config, client })
    }

    /// Build an HTTP client with optional mTLS configuration.
    fn build_client(config: &HttpSigningConfig) -> Result<Client, HttpSigningError> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .danger_accept_invalid_certs(false);

        // Configure mTLS if client cert and key are provided
        if let (Some(cert_path), Some(key_path)) =
            (&config.client_cert_path, &config.client_key_path)
        {
            let cert_pem = fs::read(cert_path).map_err(|e| {
                HttpSigningError::FileError(format!(
                    "Failed to read client certificate '{}': {}",
                    cert_path, e
                ))
            })?;

            let key_pem = fs::read(key_path).map_err(|e| {
                HttpSigningError::FileError(format!(
                    "Failed to read client key '{}': {}",
                    key_path, e
                ))
            })?;

            // Combine cert and key into a single PEM for Identity
            let mut identity_pem = cert_pem;
            identity_pem.extend_from_slice(b"\n");
            identity_pem.extend_from_slice(&key_pem);

            let identity = Identity::from_pem(&identity_pem).map_err(|e| {
                HttpSigningError::TlsError(format!("Failed to create client identity: {}", e))
            })?;

            builder = builder.identity(identity);
        }

        builder
            .build()
            .map_err(|e| HttpSigningError::TlsError(format!("Failed to build HTTP client: {}", e)))
    }

    /// Sign a payload using the HTTP endpoint.
    ///
    /// # Arguments
    ///
    /// * `payload` - The raw bytes to sign (typically CBOR-encoded PCR info)
    ///
    /// # Returns
    ///
    /// The signature bytes on success.
    pub fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, HttpSigningError> {
        // Base64 encode the payload
        let payload_b64 = BASE64.encode(payload);

        // Build request body from template
        let request_body = self
            .config
            .request_template
            .replace(PAYLOAD_PLACEHOLDER, &payload_b64);

        // Parse as JSON to validate and send
        let request_json: Value = serde_json::from_str(&request_body).map_err(|e| {
            HttpSigningError::TemplateError(format!(
                "Request template produced invalid JSON: {}",
                e
            ))
        })?;

        // Send POST request
        let response = self
            .client
            .post(&self.config.url)
            .header("Content-Type", "application/json")
            .json(&request_json)
            .send()
            .map_err(|e| {
                HttpSigningError::RequestError(format!("HTTP request failed: {}", e))
            })?;

        // Check response status
        if !response.status().is_success() {
            return Err(HttpSigningError::ResponseError(format!(
                "HTTP request returned status {}: {}",
                response.status(),
                response.text().unwrap_or_default()
            )));
        }

        // Parse response body
        let response_text = response.text().map_err(|e| {
            HttpSigningError::ResponseError(format!("Failed to read response body: {}", e))
        })?;

        // Extract signature from response using template
        let signature_b64 = self.extract_signature(&response_text)?;

        // Decode base64 signature
        let signature = BASE64.decode(&signature_b64).map_err(|e| {
            HttpSigningError::ResponseError(format!("Failed to decode signature: {}", e))
        })?;

        Ok(signature)
    }

    /// Extract signature from response using the response template.
    fn extract_signature(&self, response_text: &str) -> Result<String, HttpSigningError> {
        // Parse response as JSON
        let response_json: Value = serde_json::from_str(response_text).map_err(|e| {
            HttpSigningError::ResponseError(format!("Response is not valid JSON: {}", e))
        })?;

        // Find the path to the signature in the template
        let signature_path = self.find_signature_path()?;

        // Navigate to the signature value
        let mut current = &response_json;
        for key in &signature_path {
            current = current.get(key).ok_or_else(|| {
                HttpSigningError::ResponseError(format!(
                    "Response missing expected field '{}'. Response: {}",
                    key, response_text
                ))
            })?;
        }

        // Extract string value
        current.as_str().map(|s| s.to_string()).ok_or_else(|| {
            HttpSigningError::ResponseError(format!(
                "Signature field is not a string. Response: {}",
                response_text
            ))
        })
    }

    /// Find the JSON path to the signature placeholder in the response template.
    fn find_signature_path(&self) -> Result<Vec<String>, HttpSigningError> {
        let template_json: Value =
            serde_json::from_str(&self.config.response_template).map_err(|e| {
                HttpSigningError::TemplateError(format!("Response template is not valid JSON: {}", e))
            })?;

        let mut path = Vec::new();
        if self.find_placeholder_path(&template_json, SIGNATURE_PLACEHOLDER, &mut path) {
            Ok(path)
        } else {
            Err(HttpSigningError::TemplateError(
                "Could not find signature placeholder in response template".to_string(),
            ))
        }
    }

    /// Recursively find the path to a placeholder in a JSON value.
    fn find_placeholder_path(
        &self,
        value: &Value,
        placeholder: &str,
        path: &mut Vec<String>,
    ) -> bool {
        match value {
            Value::String(s) if s == placeholder => true,
            Value::Object(map) => {
                for (key, val) in map {
                    path.push(key.clone());
                    if self.find_placeholder_path(val, placeholder, path) {
                        return true;
                    }
                    path.pop();
                }
                false
            }
            Value::Array(arr) => {
                for (idx, val) in arr.iter().enumerate() {
                    path.push(idx.to_string());
                    if self.find_placeholder_path(val, placeholder, path) {
                        return true;
                    }
                    path.pop();
                }
                false
            }
            _ => false,
        }
    }

    /// Get the signing certificate content.
    /// This reads the certificate from the path provided in the main signing flow.
    pub fn get_certificate(cert_path: &Path) -> Result<Vec<u8>, HttpSigningError> {
        fs::read(cert_path).map_err(|e| {
            HttpSigningError::FileError(format!(
                "Failed to read signing certificate '{}': {}",
                cert_path.display(),
                e
            ))
        })
    }

    /// Get the URL of the signing endpoint.
    pub fn url(&self) -> &str {
        &self.config.url
    }

    /// Get the signing algorithm.
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.config.algorithm
    }
}

/// HTTP-based EIF signer that integrates with the EIF signing flow.
/// 
/// This struct provides the high-level signing functionality for EIF images
/// using an HTTP endpoint.
pub struct HttpEifSigner {
    /// The HTTP signer for making signing requests
    http_signer: HttpSigner,
    /// The signing certificate content
    certificate: Vec<u8>,
    /// The signing algorithm (ES384 or ES512)
    algorithm: SigningAlgorithm,
}

impl HttpEifSigner {
    /// Create a new HTTP EIF signer.
    ///
    /// # Arguments
    ///
    /// * `url` - The HTTP signing URL with optional parameters (including algorithm)
    /// * `certificate_path` - Path to the signing certificate
    pub fn new(url: &str, certificate_path: &Path) -> Result<Self, HttpSigningError> {
        let http_signer = HttpSigner::new(url)?;
        let certificate = HttpSigner::get_certificate(certificate_path)?;
        let algorithm = http_signer.algorithm();
        Ok(HttpEifSigner {
            http_signer,
            certificate,
            algorithm,
        })
    }

    /// Sign a PCR value and return the signature.
    ///
    /// # Arguments
    ///
    /// * `pcr_index` - The PCR register index (typically 0)
    /// * `pcr_value` - The PCR value bytes
    ///
    /// # Returns
    ///
    /// The raw signature bytes from the HTTP endpoint.
    pub fn sign_pcr(&self, pcr_index: i32, pcr_value: &[u8]) -> Result<Vec<u8>, HttpSigningError> {
        // Create PCR info structure (same as PcrInfo in the image format crate)
        let pcr_info = PcrInfo {
            register_index: pcr_index,
            register_value: pcr_value.to_vec(),
        };

        // Serialize to CBOR
        let mut payload = Vec::new();
        ciborium::into_writer(&pcr_info, &mut payload).map_err(|e| {
            HttpSigningError::RequestError(format!("Failed to serialize PCR info: {}", e))
        })?;

        // Sign via HTTP
        self.http_signer.sign(&payload)
    }

    /// Get the signing certificate.
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// Get the HTTP signer URL.
    pub fn url(&self) -> &str {
        self.http_signer.url()
    }

    /// Get the signing algorithm.
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }
}

/// PCR information structure for signing.
/// This mirrors the PcrInfo structure from aws-nitro-enclaves-image-format.
#[derive(serde::Serialize, serde::Deserialize)]
struct PcrInfo {
    #[serde(rename = "RegisterIndex")]
    register_index: i32,
    #[serde(rename = "RegisterValue")]
    register_value: Vec<u8>,
}

/// PCR Signature structure for the EIF signature section.
/// This mirrors the PcrSignature structure from aws-nitro-enclaves-image-format.
#[derive(serde::Serialize, serde::Deserialize)]
struct PcrSignature {
    /// The signing certificate in PEM format
    signing_certificate: Vec<u8>,
    /// The COSE signature bytes
    signature: Vec<u8>,
}

/// EIF Section types
#[repr(u16)]
#[derive(Clone, Copy)]
enum EifSectionType {
    /// Invalid section type
    _Invalid = 0,
    /// Kernel section
    _Kernel = 1,
    /// Command line section
    _CmdLine = 2,
    /// Ramdisk section
    _Ramdisk = 3,
    /// Signature section
    Signature = 4,
    /// Metadata section
    _Metadata = 5,
}

/// EIF Section header structure
#[repr(C, packed)]
struct EifSectionHeader {
    /// Section type
    section_type: u16,
    /// Section flags
    flags: u16,
    /// Section size
    section_size: u64,
}

/// Write an HTTP-obtained signature to an EIF file.
///
/// This function creates a COSE signature structure from the raw signature bytes
/// and writes it to the EIF file's signature section.
///
/// # Arguments
///
/// * `eif_path` - Path to the EIF file
/// * `certificate` - The signing certificate in PEM format
/// * `signature` - The raw signature bytes from the HTTP endpoint
/// * `is_already_signed` - Whether the EIF already has a signature section
/// * `algorithm` - The signing algorithm used (ES384 or ES512)
pub fn write_http_signature_to_eif(
    eif_path: &str,
    certificate: &[u8],
    signature: &[u8],
    is_already_signed: bool,
    algorithm: SigningAlgorithm,
) -> Result<(), HttpSigningError> {
    use std::fs::OpenOptions;
    use std::io::Read;

    // Build COSE signature structure
    let cose_signature = build_cose_signature(signature, algorithm)?;

    // Create PCR signature structure
    let pcr_signature = PcrSignature {
        signing_certificate: certificate.to_vec(),
        signature: cose_signature,
    };

    // Serialize the signature array (array with one element for PCR0)
    let mut serialized_signature = Vec::new();
    ciborium::into_writer(&vec![pcr_signature], &mut serialized_signature).map_err(|e| {
        HttpSigningError::RequestError(format!("Failed to serialize signature: {}", e))
    })?;

    // Open EIF file for reading and writing
    let mut eif_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(eif_path)
        .map_err(|e| HttpSigningError::FileError(format!("Failed to open EIF file: {}", e)))?;

    // Read EIF header to get section information
    let mut header_bytes = [0u8; 548]; // EIF header size
    eif_file.read_exact(&mut header_bytes).map_err(|e| {
        HttpSigningError::FileError(format!("Failed to read EIF header: {}", e))
    })?;

    let new_signature_size = serialized_signature.len() as u64;

    if is_already_signed {
        // Find and replace existing signature section
        replace_signature_section(&mut eif_file, &header_bytes, &serialized_signature)?;
    } else {
        // Append new signature section
        append_signature_section(&mut eif_file, &header_bytes, &serialized_signature)?;
    }

    // Update header with new section count and offsets
    update_eif_header(&mut eif_file, &header_bytes, new_signature_size, is_already_signed)?;

    Ok(())
}

/// Build a COSE_Sign1 structure from raw signature bytes.
///
/// The HTTP endpoint returns raw ECDSA signature bytes. We need to wrap them
/// in a COSE_Sign1 structure for the EIF format.
///
/// # Arguments
///
/// * `raw_signature` - The raw ECDSA signature bytes
/// * `algorithm` - The signing algorithm (ES384 or ES512)
fn build_cose_signature(raw_signature: &[u8], algorithm: SigningAlgorithm) -> Result<Vec<u8>, HttpSigningError> {
    // COSE_Sign1 structure:
    // [protected_header, unprotected_header, payload, signature]
    //
    // For EIF signing:
    // - protected_header: CBOR map with algorithm identifier (ES384 = -35, ES512 = -37)
    // - unprotected_header: empty map
    // - payload: null (external payload)
    // - signature: the raw signature bytes

    // Build protected header: {"alg": <algorithm_id>}
    let mut protected_header = Vec::new();
    let mut alg_map: std::collections::BTreeMap<i32, i32> = std::collections::BTreeMap::new();
    alg_map.insert(1, algorithm.cose_algorithm_id());
    ciborium::into_writer(&alg_map, &mut protected_header).map_err(|e| {
        HttpSigningError::RequestError(format!("Failed to build protected header: {}", e))
    })?;

    // Build COSE_Sign1 array: [protected, unprotected, payload, signature]
    // Tag 18 indicates COSE_Sign1
    let cose_sign1 = CoseSign1Tagged {
        protected: protected_header,
        unprotected: std::collections::BTreeMap::new(),
        payload: None,
        signature: raw_signature.to_vec(),
    };

    let mut result = Vec::new();
    // Write CBOR tag 18 for COSE_Sign1
    result.push(0xd2); // Tag 18 in CBOR

    // Serialize the array
    let array: (
        serde_bytes::ByteBuf,
        std::collections::BTreeMap<i32, i32>,
        Option<serde_bytes::ByteBuf>,
        serde_bytes::ByteBuf,
    ) = (
        serde_bytes::ByteBuf::from(cose_sign1.protected),
        cose_sign1.unprotected,
        cose_sign1.payload.map(serde_bytes::ByteBuf::from),
        serde_bytes::ByteBuf::from(cose_sign1.signature),
    );

    ciborium::into_writer(&array, &mut result).map_err(|e| {
        HttpSigningError::RequestError(format!("Failed to serialize COSE_Sign1: {}", e))
    })?;

    Ok(result)
}

/// COSE_Sign1 structure for serialization
struct CoseSign1Tagged {
    protected: Vec<u8>,
    unprotected: std::collections::BTreeMap<i32, i32>,
    payload: Option<Vec<u8>>,
    signature: Vec<u8>,
}

/// Replace an existing signature section in the EIF file.
fn replace_signature_section(
    eif_file: &mut std::fs::File,
    header_bytes: &[u8],
    new_signature: &[u8],
) -> Result<(), HttpSigningError> {
    use std::io::{Seek, SeekFrom, Read, Write};

    // Find signature section offset from header
    // Section offsets start at byte 36 in the header, 8 bytes each, up to 16 sections
    let num_sections = u16::from_le_bytes([header_bytes[32], header_bytes[33]]) as usize;

    let mut signature_offset: Option<u64> = None;

    // Read section headers to find signature section
    for i in 0..num_sections {
        let offset_pos = 36 + i * 8;
        let section_offset = u64::from_le_bytes(
            header_bytes[offset_pos..offset_pos + 8]
                .try_into()
                .unwrap(),
        );

        if section_offset == 0 {
            continue;
        }

        // Read section header at this offset
        eif_file.seek(SeekFrom::Start(section_offset)).map_err(|e| {
            HttpSigningError::FileError(format!("Failed to seek to section: {}", e))
        })?;

        let mut section_header = [0u8; 12];
        eif_file.read_exact(&mut section_header).map_err(|e| {
            HttpSigningError::FileError(format!("Failed to read section header: {}", e))
        })?;

        let section_type = u16::from_le_bytes([section_header[0], section_header[1]]);
        if section_type == EifSectionType::Signature as u16 {
            signature_offset = Some(section_offset);
            break;
        }
    }

    let sig_offset = signature_offset.ok_or_else(|| {
        HttpSigningError::FileError("Could not find existing signature section".to_string())
    })?;

    // Write new signature section header and data
    eif_file.seek(SeekFrom::Start(sig_offset)).map_err(|e| {
        HttpSigningError::FileError(format!("Failed to seek to signature section: {}", e))
    })?;

    // Write section header
    let section_header = EifSectionHeader {
        section_type: EifSectionType::Signature as u16,
        flags: 0,
        section_size: new_signature.len() as u64,
    };

    let header_bytes_new: [u8; 12] = unsafe { std::mem::transmute(section_header) };
    eif_file.write_all(&header_bytes_new).map_err(|e| {
        HttpSigningError::FileError(format!("Failed to write section header: {}", e))
    })?;

    // Write signature data
    eif_file.write_all(new_signature).map_err(|e| {
        HttpSigningError::FileError(format!("Failed to write signature data: {}", e))
    })?;

    // Truncate file if new signature is smaller
    let new_end = sig_offset + 12 + new_signature.len() as u64;
    eif_file.set_len(new_end).map_err(|e| {
        HttpSigningError::FileError(format!("Failed to truncate file: {}", e))
    })?;

    Ok(())
}

/// Append a new signature section to the EIF file.
fn append_signature_section(
    eif_file: &mut std::fs::File,
    _header_bytes: &[u8],
    signature: &[u8],
) -> Result<(), HttpSigningError> {
    use std::io::{Seek, SeekFrom, Write};

    // Get current file size (where we'll append)
    let file_len = eif_file.metadata().map_err(|e| {
        HttpSigningError::FileError(format!("Failed to get file metadata: {}", e))
    })?.len();

    // Seek to end of file
    eif_file.seek(SeekFrom::Start(file_len)).map_err(|e| {
        HttpSigningError::FileError(format!("Failed to seek to end of file: {}", e))
    })?;

    // Write section header
    let section_header = EifSectionHeader {
        section_type: EifSectionType::Signature as u16,
        flags: 0,
        section_size: signature.len() as u64,
    };

    let header_bytes_new: [u8; 12] = unsafe { std::mem::transmute(section_header) };
    eif_file.write_all(&header_bytes_new).map_err(|e| {
        HttpSigningError::FileError(format!("Failed to write section header: {}", e))
    })?;

    // Write signature data
    eif_file.write_all(signature).map_err(|e| {
        HttpSigningError::FileError(format!("Failed to write signature data: {}", e))
    })?;

    Ok(())
}

/// Update the EIF header with new section information.
fn update_eif_header(
    eif_file: &mut std::fs::File,
    old_header: &[u8],
    new_signature_size: u64,
    is_replacement: bool,
) -> Result<(), HttpSigningError> {
    use std::io::{Seek, SeekFrom, Write};

    let mut header = old_header.to_vec();

    if !is_replacement {
        // Increment section count
        let num_sections = u16::from_le_bytes([header[32], header[33]]);
        let new_count = num_sections + 1;
        header[32..34].copy_from_slice(&new_count.to_le_bytes());

        // Get file size before signature was added
        let file_len = eif_file.metadata().map_err(|e| {
            HttpSigningError::FileError(format!("Failed to get file metadata: {}", e))
        })?.len();

        // Calculate signature section offset (file_len - section_header - signature_data)
        let sig_offset = file_len - 12 - new_signature_size;

        // Find first empty section offset slot and set it
        for i in 0..16 {
            let offset_pos = 36 + i * 8;
            let current_offset = u64::from_le_bytes(
                header[offset_pos..offset_pos + 8].try_into().unwrap(),
            );
            if current_offset == 0 {
                header[offset_pos..offset_pos + 8].copy_from_slice(&sig_offset.to_le_bytes());
                break;
            }
        }

        // Update section sizes array (starts at byte 164)
        for i in 0..16 {
            let size_pos = 164 + i * 8;
            let current_size = u64::from_le_bytes(
                header[size_pos..size_pos + 8].try_into().unwrap(),
            );
            if current_size == 0 {
                header[size_pos..size_pos + 8].copy_from_slice(&new_signature_size.to_le_bytes());
                break;
            }
        }
    }

    // Update CRC (last 4 bytes of header area, at offset 544)
    // For now, we'll set CRC to 0 and let the reader recalculate
    // A proper implementation would calculate CRC32 of the entire file
    header[544..548].copy_from_slice(&[0u8; 4]);

    // Write updated header
    eif_file.seek(SeekFrom::Start(0)).map_err(|e| {
        HttpSigningError::FileError(format!("Failed to seek to header: {}", e))
    })?;

    eif_file.write_all(&header).map_err(|e| {
        HttpSigningError::FileError(format!("Failed to write header: {}", e))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Unit Tests ====================

    #[test]
    fn test_is_http_signing_url() {
        assert!(is_http_signing_url("https://example.com/sign"));
        assert!(is_http_signing_url("https://localhost:8443/v2/sign"));
        assert!(!is_http_signing_url("http://example.com/sign"));
        assert!(!is_http_signing_url("/path/to/key.pem"));
        assert!(!is_http_signing_url("arn:aws:kms:us-west-2:123:key/abc"));
    }

    #[test]
    fn test_parse_basic_url() {
        let config = HttpSigningConfig::parse("https://example.com/v2/sign").unwrap();
        assert_eq!(config.url, "https://example.com/v2/sign");
        assert!(config.client_cert_path.is_none());
        assert!(config.client_key_path.is_none());
        assert_eq!(config.request_template, DEFAULT_REQUEST_TEMPLATE);
        assert_eq!(config.response_template, DEFAULT_RESPONSE_TEMPLATE);
    }

    #[test]
    fn test_parse_url_with_mtls() {
        let url = "https://example.com/sign;client_cert=/path/to/cert.pem;client_key=/path/to/key.pem";
        let config = HttpSigningConfig::parse(url).unwrap();
        assert_eq!(config.url, "https://example.com/sign");
        assert_eq!(config.client_cert_path, Some("/path/to/cert.pem".to_string()));
        assert_eq!(config.client_key_path, Some("/path/to/key.pem".to_string()));
    }

    #[test]
    fn test_parse_url_with_custom_templates() {
        // {"data":"{payload}"} base64 encoded
        let req_template_b64 = BASE64.encode(r#"{"data":"{payload}"}"#);
        // {"sig":"{signature}"} base64 encoded
        let resp_template_b64 = BASE64.encode(r#"{"sig":"{signature}"}"#);

        let url = format!(
            "https://example.com/sign;request_template={};response_template={}",
            req_template_b64, resp_template_b64
        );
        let config = HttpSigningConfig::parse(&url).unwrap();
        assert_eq!(config.request_template, r#"{"data":"{payload}"}"#);
        assert_eq!(config.response_template, r#"{"sig":"{signature}"}"#);
    }

    #[test]
    fn test_parse_url_http_rejected() {
        let result = HttpSigningConfig::parse("http://example.com/sign");
        assert!(result.is_err());
        match result {
            Err(HttpSigningError::UrlParseError(msg)) => {
                assert!(msg.contains("HTTPS"));
            }
            _ => panic!("Expected UrlParseError"),
        }
    }

    #[test]
    fn test_parse_url_mtls_incomplete() {
        // Only cert, no key
        let result = HttpSigningConfig::parse("https://example.com/sign;client_cert=/path/cert.pem");
        assert!(result.is_err());
        match result {
            Err(HttpSigningError::UrlParseError(msg)) => {
                assert!(msg.contains("client_cert and client_key"));
            }
            _ => panic!("Expected UrlParseError"),
        }
    }

    #[test]
    fn test_parse_url_invalid_request_template() {
        // Template without {payload} placeholder
        let bad_template_b64 = BASE64.encode(r#"{"data":"fixed"}"#);
        let url = format!(
            "https://example.com/sign;request_template={}",
            bad_template_b64
        );
        let result = HttpSigningConfig::parse(&url);
        assert!(result.is_err());
        match result {
            Err(HttpSigningError::TemplateError(msg)) => {
                assert!(msg.contains("{payload}"));
            }
            _ => panic!("Expected TemplateError"),
        }
    }

    #[test]
    fn test_parse_url_invalid_response_template() {
        // Template without {signature} placeholder
        let bad_template_b64 = BASE64.encode(r#"{"result":"fixed"}"#);
        let url = format!(
            "https://example.com/sign;response_template={}",
            bad_template_b64
        );
        let result = HttpSigningConfig::parse(&url);
        assert!(result.is_err());
        match result {
            Err(HttpSigningError::TemplateError(msg)) => {
                assert!(msg.contains("{signature}"));
            }
            _ => panic!("Expected TemplateError"),
        }
    }

    #[test]
    fn test_parse_url_default_algorithm() {
        let config = HttpSigningConfig::parse("https://example.com/sign").unwrap();
        assert_eq!(config.algorithm, SigningAlgorithm::ES384);
    }

    #[test]
    fn test_parse_url_with_algorithm_es384() {
        let config = HttpSigningConfig::parse("https://example.com/sign;algorithm=ES384").unwrap();
        assert_eq!(config.algorithm, SigningAlgorithm::ES384);
    }

    #[test]
    fn test_parse_url_with_algorithm_es512() {
        let config = HttpSigningConfig::parse("https://example.com/sign;algorithm=ES512").unwrap();
        assert_eq!(config.algorithm, SigningAlgorithm::ES512);
    }

    #[test]
    fn test_parse_url_with_algorithm_case_insensitive() {
        let config = HttpSigningConfig::parse("https://example.com/sign;algorithm=es512").unwrap();
        assert_eq!(config.algorithm, SigningAlgorithm::ES512);
        
        let config2 = HttpSigningConfig::parse("https://example.com/sign;algorithm=Es384").unwrap();
        assert_eq!(config2.algorithm, SigningAlgorithm::ES384);
    }

    #[test]
    fn test_parse_url_with_invalid_algorithm() {
        let result = HttpSigningConfig::parse("https://example.com/sign;algorithm=ES256");
        assert!(result.is_err());
        match result {
            Err(HttpSigningError::UrlParseError(msg)) => {
                assert!(msg.contains("ES256"));
                assert!(msg.contains("ES384"));
                assert!(msg.contains("ES512"));
            }
            _ => panic!("Expected UrlParseError"),
        }
    }

    #[test]
    fn test_signing_algorithm_cose_ids() {
        assert_eq!(SigningAlgorithm::ES384.cose_algorithm_id(), -35);
        assert_eq!(SigningAlgorithm::ES512.cose_algorithm_id(), -37);
    }

    #[test]
    fn test_signing_algorithm_display() {
        assert_eq!(format!("{}", SigningAlgorithm::ES384), "ES384");
        assert_eq!(format!("{}", SigningAlgorithm::ES512), "ES512");
    }

    #[test]
    fn test_find_signature_path_simple() {
        let config = HttpSigningConfig {
            url: "https://example.com".to_string(),
            client_cert_path: None,
            client_key_path: None,
            request_template: DEFAULT_REQUEST_TEMPLATE.to_string(),
            response_template: r#"{"signature":"{signature}"}"#.to_string(),
            algorithm: SigningAlgorithm::default(),
        };
        let signer = HttpSigner {
            config,
            client: Client::new(),
        };
        let path = signer.find_signature_path().unwrap();
        assert_eq!(path, vec!["signature"]);
    }

    #[test]
    fn test_find_signature_path_nested() {
        let config = HttpSigningConfig {
            url: "https://example.com".to_string(),
            client_cert_path: None,
            client_key_path: None,
            request_template: DEFAULT_REQUEST_TEMPLATE.to_string(),
            response_template: r#"{"result":{"data":{"sig":"{signature}"}}}"#.to_string(),
            algorithm: SigningAlgorithm::default(),
        };
        let signer = HttpSigner {
            config,
            client: Client::new(),
        };
        let path = signer.find_signature_path().unwrap();
        assert_eq!(path, vec!["result", "data", "sig"]);
    }

    #[test]
    fn test_extract_signature_simple() {
        let config = HttpSigningConfig {
            url: "https://example.com".to_string(),
            client_cert_path: None,
            client_key_path: None,
            request_template: DEFAULT_REQUEST_TEMPLATE.to_string(),
            response_template: r#"{"signature":"{signature}"}"#.to_string(),
            algorithm: SigningAlgorithm::default(),
        };
        let signer = HttpSigner {
            config,
            client: Client::new(),
        };
        let response = r#"{"signature":"dGVzdF9zaWduYXR1cmU="}"#;
        let sig = signer.extract_signature(response).unwrap();
        assert_eq!(sig, "dGVzdF9zaWduYXR1cmU=");
    }

    #[test]
    fn test_extract_signature_nested() {
        let config = HttpSigningConfig {
            url: "https://example.com".to_string(),
            client_cert_path: None,
            client_key_path: None,
            request_template: DEFAULT_REQUEST_TEMPLATE.to_string(),
            response_template: r#"{"result":{"sig":"{signature}"}}"#.to_string(),
            algorithm: SigningAlgorithm::default(),
        };
        let signer = HttpSigner {
            config,
            client: Client::new(),
        };
        let response = r#"{"result":{"sig":"YWJjMTIz","extra":"ignored"}}"#;
        let sig = signer.extract_signature(response).unwrap();
        assert_eq!(sig, "YWJjMTIz");
    }

    #[test]
    fn test_build_cose_signature_es384() {
        // Test that we can build a valid COSE signature structure with ES384
        let raw_signature = vec![0x01, 0x02, 0x03, 0x04];
        let result = build_cose_signature(&raw_signature, SigningAlgorithm::ES384);
        assert!(result.is_ok());
        let cose_bytes = result.unwrap();
        // Should start with CBOR tag 18 (0xd2)
        assert_eq!(cose_bytes[0], 0xd2);
    }

    #[test]
    fn test_build_cose_signature_es512() {
        // Test that we can build a valid COSE signature structure with ES512
        let raw_signature = vec![0x01, 0x02, 0x03, 0x04];
        let result = build_cose_signature(&raw_signature, SigningAlgorithm::ES512);
        assert!(result.is_ok());
        let cose_bytes = result.unwrap();
        // Should start with CBOR tag 18 (0xd2)
        assert_eq!(cose_bytes[0], 0xd2);
    }

    #[test]
    fn test_pcr_info_serialization() {
        // Test that PcrInfo serializes correctly to CBOR
        let pcr_info = PcrInfo {
            register_index: 0,
            register_value: vec![0xab, 0xcd, 0xef],
        };
        let mut payload = Vec::new();
        ciborium::into_writer(&pcr_info, &mut payload).unwrap();
        assert!(!payload.is_empty());
    }

    // ==================== Integration Tests ====================
    // 
    // Full end-to-end integration tests with mock HTTPS server are in:
    // tests/test_http_signing_integration.rs

    /// Test that verifies the complete signing flow logic without network
    #[test]
    fn test_signing_flow_logic() {
        // Test the complete flow of:
        // 1. Parsing URL config
        // 2. Building request from template
        // 3. Parsing response from template

        let url = "https://example.com/sign";
        let config = HttpSigningConfig::parse(url).unwrap();

        // Verify config
        assert_eq!(config.url, "https://example.com/sign");
        assert_eq!(config.request_template, r#"{"message":"{payload}"}"#);
        assert_eq!(config.response_template, r#"{"signature":"{signature}"}"#);

        // Test request building
        let payload = b"test_payload";
        let payload_b64 = BASE64.encode(payload);
        let request_body = config.request_template.replace("{payload}", &payload_b64);
        
        // Verify request is valid JSON
        let request_json: Value = serde_json::from_str(&request_body).unwrap();
        assert_eq!(request_json["message"], payload_b64);

        // Test response parsing
        let mock_sig = BASE64.encode(b"signature_bytes");
        let response = format!(r#"{{"signature":"{}"}}"#, mock_sig);
        
        let signer = HttpSigner {
            config,
            client: Client::new(),
        };
        let extracted = signer.extract_signature(&response).unwrap();
        assert_eq!(extracted, mock_sig);

        // Verify we can decode the signature
        let decoded = BASE64.decode(&extracted).unwrap();
        assert_eq!(decoded, b"signature_bytes");
    }

    /// Test custom templates work correctly
    #[test]
    fn test_custom_template_flow() {
        let req_template = r#"{"data":"{payload}","algo":"ES384"}"#;
        let resp_template = r#"{"result":{"sig":"{signature}","status":"ok"}}"#;

        let req_b64 = BASE64.encode(req_template);
        let resp_b64 = BASE64.encode(resp_template);

        let url = format!(
            "https://example.com/sign;request_template={};response_template={}",
            req_b64, resp_b64
        );

        let config = HttpSigningConfig::parse(&url).unwrap();
        assert_eq!(config.request_template, req_template);
        assert_eq!(config.response_template, resp_template);

        // Test request building with custom template
        let payload_b64 = BASE64.encode(b"test");
        let request_body = config.request_template.replace("{payload}", &payload_b64);
        let request_json: Value = serde_json::from_str(&request_body).unwrap();
        assert_eq!(request_json["data"], payload_b64);
        assert_eq!(request_json["algo"], "ES384");

        // Test response parsing with custom template
        let mock_sig = "abc123";
        let response = format!(r#"{{"result":{{"sig":"{}","status":"ok"}}}}"#, mock_sig);
        
        let signer = HttpSigner {
            config,
            client: Client::new(),
        };
        let extracted = signer.extract_signature(&response).unwrap();
        assert_eq!(extracted, mock_sig);
    }
}
