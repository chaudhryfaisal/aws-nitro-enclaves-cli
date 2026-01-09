# HTTP Signing Design Document

## Overview

This document describes the design and implementation of HTTP-based signing support for AWS Nitro Enclaves CLI. This feature enables users to sign enclave images using external signing services via HTTPS endpoints, with optional mutual TLS (mTLS) authentication and customizable request/response formats.

## Motivation

Organizations often have centralized signing services or Hardware Security Modules (HSMs) that manage cryptographic keys. Rather than requiring private keys to be available locally or exclusively through AWS KMS, this feature allows integration with any HTTP-based signing service.

## URL Format

```
https://host:port/path;algorithm={algo};client_cert={path};client_key={path};request_template={base64};response_template={base64}
```

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| Base URL | Yes | - | HTTPS endpoint URL |
| `algorithm` | No | `ES384` | Signing algorithm: `ES384` or `ES512` |
| `client_cert` | No | - | Path to client certificate for mTLS |
| `client_key` | No | - | Path to client private key for mTLS |
| `request_template` | No | `{"message":"{payload}"}` | Base64-encoded JSON request template |
| `response_template` | No | `{"signature":"{signature}"}` | Base64-encoded JSON response template |

## Algorithm Support

| Algorithm | COSE ID | Curve | Hash | Key Length | Signature Size |
|-----------|---------|-------|------|------------|----------------|
| ES384 | -35 | P-384 | SHA-384 | 48 bytes | 96 bytes (R‖S) |
| ES512 | -36 | P-521 | SHA-512 | 66 bytes | 132 bytes (R‖S) |

**Note**: ES256 is intentionally not supported for HTTP signing as the existing codebase uses ES384/ES512 for EIF signing.

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         aws-nitro-enclaves-cli                           │
│                                                                          │
│  User provides: --private-key "https://signing.example.com/sign;..."    │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    aws-nitro-enclaves-image-format                       │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                         SignKeyData                                │  │
│  │  - Detects key type from --private-key value                      │  │
│  │  - Creates appropriate SignKey variant                            │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                     │
│                                    ▼                                     │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                           SignKey                                  │  │
│  │  enum SignKey {                                                   │  │
│  │      LocalPrivateKey(Vec<u8>),  // PEM-encoded local key          │  │
│  │      KmsKey(Arc<KmsKey>),       // AWS KMS key                    │  │
│  │      HttpKey(Arc<HttpSigningKey>), // HTTP signing endpoint       │  │
│  │  }                                                                │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                     │
│                                    ▼                                     │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                          EifSigner                                 │  │
│  │  - Uses SignKey to sign PCR values                                │  │
│  │  - Creates COSE_Sign1 structures via aws-nitro-enclaves-cose      │  │
│  │  - Writes signatures to EIF files                                 │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       aws-nitro-enclaves-cose                            │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                       HttpSigningKey                               │  │
│  │  - Implements SigningPrivateKey trait                             │  │
│  │  - Parses URL with options                                        │  │
│  │  - Configures HTTP client with optional mTLS                      │  │
│  │  - Sends signing requests using templates                         │  │
│  │  - Extracts signatures from responses                             │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                     │
│                                    ▼                                     │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                         CoseSign1                                  │  │
│  │  - Wraps signature in COSE_Sign1 structure                        │  │
│  │  - Handles protected/unprotected headers                          │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      External Signing Service                            │
│  - Receives POST request with JSON body                                  │
│  - Signs the payload using ECDSA (P-384 or P-521)                       │
│  - Returns signature in JSON response                                    │
└─────────────────────────────────────────────────────────────────────────┘
```

### Signing Flow

1. **URL Detection**: `SignKeyInfo::new()` checks if the key location starts with `https://`
2. **Key Creation**: `SignKeyData::new()` creates `SignKey::HttpKey` with `HttpSigningKey::new()`
3. **URL Parsing**: `HttpSigningConfig::parse()` extracts:
   - Base URL
   - Algorithm (ES384/ES512)
   - mTLS credentials (optional)
   - Request/response templates (optional)
4. **Client Setup**: HTTP client is configured with:
   - 30-second timeout
   - TLS certificate validation
   - Optional mTLS identity
5. **Signing Request**:
   - Payload is base64-encoded
   - Request body is built from template
   - POST request sent to endpoint
6. **Response Processing**:
   - Response JSON is parsed
   - Signature is extracted using template path
   - Base64-decoded signature is returned
7. **COSE Wrapping**: `CoseSign1::new()` wraps the signature
8. **EIF Update**: Signature section is written to EIF file

## Template System

### Request Template

The request template defines the JSON structure sent to the signing endpoint.

**Default**: `{"message":"{payload}"}`

**Placeholder**: `{payload}` - Replaced with base64-encoded data to sign

**Example custom template**:
```json
{"data": "{payload}", "algorithm": "ES384", "keyId": "my-key"}
```

### Response Template

The response template defines where to find the signature in the JSON response.

**Default**: `{"signature":"{signature}"}`

**Placeholder**: `{signature}` - Path to the base64-encoded signature

**Example custom template** (for nested response):
```json
{"result": {"sig": "{signature}"}, "status": "ok"}
```

The implementation recursively searches the template JSON to find the path to `{signature}`, then uses that path to extract the value from the actual response.

## Security Considerations

1. **HTTPS Only**: HTTP URLs are rejected to ensure transport security
2. **Certificate Validation**: Server certificates are validated by default
3. **mTLS Support**: Client certificates can be used for mutual authentication
4. **Timeout**: 30-second timeout prevents hanging on unresponsive endpoints
5. **No Credential Logging**: Sensitive data is not logged

## Error Handling

| Error Type | Description |
|------------|-------------|
| `CoseError::UnsupportedError` | Invalid URL, missing parameters, unsupported algorithm |
| `CoseError::SignatureError` | HTTP request failed, invalid response, missing signature |

## Testing

### Unit Tests (aws-nitro-enclaves-cose)

- URL parsing with various parameter combinations
- Template validation
- Algorithm parsing (ES384, ES512)
- mTLS configuration validation

### CLI Argument Tests (aws-nitro-enclaves-cli)

- `build_signed_enclave_correct_command_http_signing`
- `build_signed_enclave_correct_command_http_signing_with_mtls`
- `build_signed_enclave_correct_command_http_signing_with_algorithm`
- `sign_enclave_correct_command_http_signing`

## Usage Examples

### Basic HTTP Signing
```bash
nitro-cli build-enclave \
  --docker-uri hello:latest \
  --output-file hello.eif \
  --signing-certificate cert.pem \
  --private-key "https://signing.example.com/v2/core/sign/ecdsa"
```

### With ES512 Algorithm
```bash
nitro-cli build-enclave \
  --docker-uri hello:latest \
  --output-file hello.eif \
  --signing-certificate cert.pem \
  --private-key "https://signing.example.com/sign;algorithm=ES512"
```

### With Mutual TLS
```bash
nitro-cli build-enclave \
  --docker-uri hello:latest \
  --output-file hello.eif \
  --signing-certificate cert.pem \
  --private-key "https://signing.example.com/sign;client_cert=/path/client.crt;client_key=/path/client.key"
```

### With Custom Templates
```bash
# Request: {"data":"{payload}"}
# Response: {"sig":"{signature}"}
nitro-cli build-enclave \
  --docker-uri hello:latest \
  --output-file hello.eif \
  --signing-certificate cert.pem \
  --private-key "https://signing.example.com/sign;request_template=eyJkYXRhIjoie3BheWxvYWR9In0=;response_template=eyJzaWciOiJ7c2lnbmF0dXJlfSJ9"
```

## Endpoint Implementation Requirements

A compatible signing endpoint must:

1. Accept `POST` requests with `Content-Type: application/json`
2. Parse the base64-encoded payload from the request body
3. Sign using ECDSA with the appropriate curve:
   - P-384 for ES384
   - P-521 for ES512
4. Return the signature as base64-encoded raw bytes (R || S format)
5. Use the expected response JSON structure
