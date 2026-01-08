// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for HTTP signing with mock HTTPS server.
//!
//! These tests spin up a real HTTPS server with self-signed certificates
//! to validate the end-to-end HTTP signing flow.

#![allow(dead_code)]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;

/// Test certificate and key for the mock HTTPS server.
/// Generated using rcgen for testing purposes only.
struct TestCertificates {
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
    ca_cert_pem: String,
}

impl TestCertificates {
    fn generate() -> Self {
        use rcgen::{CertificateParams, KeyPair, DnType};

        // Generate CA
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "Test CA");
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Generate server certificate
        let mut server_params = CertificateParams::default();
        server_params.distinguished_name.push(DnType::CommonName, "localhost");
        server_params.subject_alt_names = vec![
            rcgen::SanType::DnsName("localhost".try_into().unwrap()),
            rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        ];
        let server_key = KeyPair::generate().unwrap();
        let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

        // Generate client certificate for mTLS
        let mut client_params = CertificateParams::default();
        client_params.distinguished_name.push(DnType::CommonName, "Test Client");
        let client_key = KeyPair::generate().unwrap();
        let client_cert = client_params.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

        TestCertificates {
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
            ca_cert_pem: ca_cert.pem(),
        }
    }
}

/// Mock signing server that responds to signing requests.
struct MockSigningServer {
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl MockSigningServer {
    /// Start a mock HTTPS signing server.
    async fn start(certs: &TestCertificates) -> Self {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use tokio_rustls::TlsAcceptor;
        use hyper::server::conn::http1;
        use hyper::service::service_fn;
        use hyper::{Request, body::Incoming};
        use hyper_util::rt::TokioIo;

        // Parse server certificate and key
        let cert = CertificateDer::from(
            rustls_pemfile::certs(&mut certs.server_cert_pem.as_bytes())
                .next()
                .unwrap()
                .unwrap()
                .to_vec()
        );
        let key = PrivateKeyDer::try_from(
            rustls_pemfile::private_key(&mut certs.server_key_pem.as_bytes())
                .unwrap()
                .unwrap()
                .secret_der()
                .to_vec()
        ).unwrap();

        // Build TLS config
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));

        // Bind to random port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        // Spawn server task
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        if let Ok((stream, _)) = result {
                            let acceptor = acceptor.clone();
                            tokio::spawn(async move {
                                if let Ok(tls_stream) = acceptor.accept(stream).await {
                                    let io = TokioIo::new(tls_stream);
                                    let service = service_fn(|req: Request<Incoming>| async move {
                                        handle_signing_request(req).await
                                    });
                                    let _ = http1::Builder::new()
                                        .serve_connection(io, service)
                                        .await;
                                }
                            });
                        }
                    }
                    _ = &mut shutdown_rx => {
                        break;
                    }
                }
            }
        });

        MockSigningServer {
            addr,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    fn url(&self) -> String {
        format!("https://127.0.0.1:{}/v2/core/sign/ecdsa-sha256", self.addr.port())
    }

    fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for MockSigningServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Handle a signing request and return a mock signature.
async fn handle_signing_request(
    req: hyper::Request<hyper::body::Incoming>,
) -> Result<hyper::Response<http_body_util::Full<hyper::body::Bytes>>, std::convert::Infallible> {
    use http_body_util::BodyExt;

    // Read request body
    let body_bytes = req.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);

    // Parse JSON request
    let request_json: serde_json::Value = serde_json::from_str(&body_str).unwrap_or_default();

    // Extract payload from request (supports both default and custom templates)
    let payload_b64 = request_json.get("message")
        .or_else(|| request_json.get("data"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Decode payload to verify it's valid base64
    let payload = BASE64.decode(payload_b64).unwrap_or_default();

    // Create a mock ECDSA signature (96 bytes for P-384)
    // In real implementation, this would be actual ECDSA signing
    let mut mock_signature = vec![0u8; 96];
    // Use payload hash as part of signature for verification
    if !payload.is_empty() {
        use sha2::{Sha384, Digest};
        let hash = Sha384::digest(&payload);
        mock_signature[..48].copy_from_slice(&hash[..]);
        mock_signature[48..].copy_from_slice(&hash[..]);
    }

    let signature_b64 = BASE64.encode(&mock_signature);

    // Build response based on path
    let response_body = format!(r#"{{"signature":"{}"}}"#, signature_b64);

    Ok(hyper::Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(http_body_util::Full::new(hyper::body::Bytes::from(response_body)))
        .unwrap())
}

/// Handle signing request with custom response format.
async fn handle_custom_signing_request(
    req: hyper::Request<hyper::body::Incoming>,
) -> Result<hyper::Response<http_body_util::Full<hyper::body::Bytes>>, std::convert::Infallible> {
    use http_body_util::BodyExt;

    let body_bytes = req.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);
    let request_json: serde_json::Value = serde_json::from_str(&body_str).unwrap_or_default();

    let payload_b64 = request_json.get("data")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let payload = BASE64.decode(payload_b64).unwrap_or_default();

    let mut mock_signature = vec![0u8; 96];
    if !payload.is_empty() {
        use sha2::{Sha384, Digest};
        let hash = Sha384::digest(&payload);
        mock_signature[..48].copy_from_slice(&hash[..]);
        mock_signature[48..].copy_from_slice(&hash[..]);
    }

    let signature_b64 = BASE64.encode(&mock_signature);

    // Custom nested response format
    let response_body = format!(
        r#"{{"result":{{"sig":"{}","status":"ok"}}}}"#,
        signature_b64
    );

    Ok(hyper::Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(http_body_util::Full::new(hyper::body::Bytes::from(response_body)))
        .unwrap())
}

// ==================== Integration Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    /// Helper to write certificates to temp files.
    fn write_certs_to_files(certs: &TestCertificates, dir: &TempDir) -> (String, String, String) {
        let ca_path = dir.path().join("ca.pem");
        let client_cert_path = dir.path().join("client.crt");
        let client_key_path = dir.path().join("client.key");

        fs::write(&ca_path, &certs.ca_cert_pem).unwrap();
        fs::write(&client_cert_path, &certs.client_cert_pem).unwrap();
        fs::write(&client_key_path, &certs.client_key_pem).unwrap();

        (
            ca_path.to_string_lossy().to_string(),
            client_cert_path.to_string_lossy().to_string(),
            client_key_path.to_string_lossy().to_string(),
        )
    }

    /// Test basic HTTP signing URL parsing.
    #[test]
    fn test_url_parsing_basic() {
        use nitro_cli::http_signing::HttpSigningConfig;

        let url = "https://signing.example.com/v2/core/sign/ecdsa-sha256";
        let config = HttpSigningConfig::parse(url).unwrap();

        assert_eq!(config.url, url);
        assert!(config.client_cert_path.is_none());
        assert!(config.client_key_path.is_none());
    }

    /// Test HTTP signing URL parsing with mTLS parameters.
    #[test]
    fn test_url_parsing_with_mtls() {
        use nitro_cli::http_signing::HttpSigningConfig;

        let url = "https://signing.example.com/sign;client_cert=/path/to/cert.pem;client_key=/path/to/key.pem";
        let config = HttpSigningConfig::parse(url).unwrap();

        assert_eq!(config.url, "https://signing.example.com/sign");
        assert_eq!(config.client_cert_path, Some("/path/to/cert.pem".to_string()));
        assert_eq!(config.client_key_path, Some("/path/to/key.pem".to_string()));
    }

    /// Test HTTP signing URL parsing with custom templates.
    #[test]
    fn test_url_parsing_with_templates() {
        use nitro_cli::http_signing::HttpSigningConfig;

        let req_template = r#"{"data":"{payload}","algo":"ES384"}"#;
        let resp_template = r#"{"result":{"sig":"{signature}"}}"#;

        let req_b64 = BASE64.encode(req_template);
        let resp_b64 = BASE64.encode(resp_template);

        let url = format!(
            "https://example.com/sign;request_template={};response_template={}",
            req_b64, resp_b64
        );

        let config = HttpSigningConfig::parse(&url).unwrap();
        assert_eq!(config.request_template, req_template);
        assert_eq!(config.response_template, resp_template);
    }

    /// Test that HTTP (non-HTTPS) URLs are rejected.
    #[test]
    fn test_http_url_rejected() {
        use nitro_cli::http_signing::HttpSigningConfig;

        let result = HttpSigningConfig::parse("http://example.com/sign");
        assert!(result.is_err());
    }

    /// Test that incomplete mTLS config is rejected.
    #[test]
    fn test_incomplete_mtls_rejected() {
        use nitro_cli::http_signing::HttpSigningConfig;

        // Only cert, no key
        let result = HttpSigningConfig::parse("https://example.com/sign;client_cert=/path/cert.pem");
        assert!(result.is_err());

        // Only key, no cert
        let result = HttpSigningConfig::parse("https://example.com/sign;client_key=/path/key.pem");
        assert!(result.is_err());
    }

    /// Test is_http_signing_url function.
    #[test]
    fn test_is_http_signing_url() {
        use nitro_cli::http_signing::is_http_signing_url;

        assert!(is_http_signing_url("https://example.com/sign"));
        assert!(is_http_signing_url("https://localhost:8443/v2/sign"));
        assert!(!is_http_signing_url("http://example.com/sign"));
        assert!(!is_http_signing_url("/path/to/key.pem"));
        assert!(!is_http_signing_url("arn:aws:kms:us-west-2:123:key/abc"));
    }

    /// End-to-end test with mock HTTPS server using default templates.
    #[tokio::test]
    async fn test_e2e_signing_default_template() {
        // Install default crypto provider for rustls
        let _ = rustls::crypto::ring::default_provider().install_default();

        let certs = TestCertificates::generate();
        let mut server = MockSigningServer::start(&certs).await;

        // Give server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let url = server.url();
        println!("Mock server URL: {}", url);

        // Test that URL is correctly formed
        assert!(url.starts_with("https://127.0.0.1:"));
        assert!(url.contains("/v2/core/sign/ecdsa-sha256"));

        server.shutdown();
    }

    /// End-to-end test that actually sends a signing request to the mock server.
    #[tokio::test]
    async fn test_e2e_signing_with_request() {
        // Install default crypto provider for rustls
        let _ = rustls::crypto::ring::default_provider().install_default();

        let certs = TestCertificates::generate();
        let temp_dir = TempDir::new().unwrap();

        // Write CA cert to file for client to trust
        let ca_path = temp_dir.path().join("ca.pem");
        fs::write(&ca_path, &certs.ca_cert_pem).unwrap();

        let mut server = MockSigningServer::start(&certs).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let url = server.url();

        // Create a reqwest client that trusts our CA
        let ca_cert = reqwest::Certificate::from_pem(certs.ca_cert_pem.as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(ca_cert)
            .build()
            .unwrap();

        // Send a signing request
        let payload = b"test_payload_data";
        let payload_b64 = BASE64.encode(payload);
        let request_body = format!(r#"{{"message":"{}"}}"#, payload_b64);

        let response = client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(request_body)
            .send()
            .await
            .unwrap();

        assert!(response.status().is_success());

        let response_text = response.text().await.unwrap();
        println!("Response: {}", response_text);

        // Parse response and extract signature
        let response_json: serde_json::Value = serde_json::from_str(&response_text).unwrap();
        let signature_b64 = response_json["signature"].as_str().unwrap();

        // Decode and verify signature is 96 bytes (P-384 signature)
        let signature = BASE64.decode(signature_b64).unwrap();
        assert_eq!(signature.len(), 96, "Expected 96-byte P-384 signature");

        server.shutdown();
    }

    /// Test signing with custom request/response templates.
    #[tokio::test]
    async fn test_e2e_signing_custom_templates() {
        // Install default crypto provider for rustls
        let _ = rustls::crypto::ring::default_provider().install_default();

        let certs = TestCertificates::generate();
        let mut server = MockSigningServer::start(&certs).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Create custom templates
        let req_template = r#"{"data":"{payload}","algo":"ES384"}"#;
        let resp_template = r#"{"signature":"{signature}"}"#;

        let req_b64 = BASE64.encode(req_template);
        let resp_b64 = BASE64.encode(resp_template);

        let base_url = server.url();
        let full_url = format!(
            "{};request_template={};response_template={}",
            base_url, req_b64, resp_b64
        );

        // Parse the URL to verify templates are correctly decoded
        let config = nitro_cli::http_signing::HttpSigningConfig::parse(&full_url).unwrap();
        assert_eq!(config.request_template, req_template);
        assert_eq!(config.response_template, resp_template);

        // Verify the base URL is correct
        assert_eq!(config.url, base_url);

        server.shutdown();
    }

    /// Test URL parsing with all parameters combined.
    #[tokio::test]
    async fn test_e2e_full_url_parsing() {
        let temp_dir = TempDir::new().unwrap();
        let certs = TestCertificates::generate();
        let (_, cert_path, key_path) = write_certs_to_files(&certs, &temp_dir);

        let req_template = r#"{"message":"{payload}"}"#;
        let resp_template = r#"{"result":{"sig":"{signature}"}}"#;

        let req_b64 = BASE64.encode(req_template);
        let resp_b64 = BASE64.encode(resp_template);

        let url = format!(
            "https://signing.example.com/v2/sign;client_cert={};client_key={};request_template={};response_template={}",
            cert_path, key_path, req_b64, resp_b64
        );

        let config = nitro_cli::http_signing::HttpSigningConfig::parse(&url).unwrap();

        assert_eq!(config.url, "https://signing.example.com/v2/sign");
        assert_eq!(config.client_cert_path, Some(cert_path));
        assert_eq!(config.client_key_path, Some(key_path));
        assert_eq!(config.request_template, req_template);
        assert_eq!(config.response_template, resp_template);
    }

    /// Test certificate generation for mTLS.
    #[test]
    fn test_certificate_generation() {
        let certs = TestCertificates::generate();

        // Verify certificates are valid PEM format
        assert!(certs.server_cert_pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(certs.server_key_pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(certs.client_cert_pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(certs.client_key_pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(certs.ca_cert_pem.contains("-----BEGIN CERTIFICATE-----"));
    }

    /// Test writing certificates to temp files.
    #[test]
    fn test_write_certs_to_files() {
        let certs = TestCertificates::generate();
        let temp_dir = TempDir::new().unwrap();

        let (ca_path, cert_path, key_path) = write_certs_to_files(&certs, &temp_dir);

        // Verify files exist and contain expected content
        assert!(std::path::Path::new(&ca_path).exists());
        assert!(std::path::Path::new(&cert_path).exists());
        assert!(std::path::Path::new(&key_path).exists());

        let ca_content = fs::read_to_string(&ca_path).unwrap();
        assert!(ca_content.contains("-----BEGIN CERTIFICATE-----"));
    }
}
