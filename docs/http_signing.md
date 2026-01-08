# HTTP Signing Support

## Overview

This feature adds support for generic signing over HTTP endpoints with optional mutual TLS (mTLS), allowing users to use external signing services instead of local private keys or AWS KMS.

The `--private-key` parameter now supports three types of values:
1. **Local file path**: `/path/to/private-key.pem`
2. **AWS KMS ARN**: `arn:aws:kms:region:account:key/key-id`
3. **HTTPS signing URL**: `https://host:port/path[;options]`

## URL Format

```
https://host:port/path;algorithm={algo};client_cert={path};client_key={path};request_template={base64};response_template={base64}
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| Base URL | Yes | The HTTPS endpoint URL (e.g., `https://signing.example.com/v2/core/sign/ecdsa-sha256`) |
| `algorithm` | No | Signing algorithm: `ES384` (default) or `ES512` |
| `client_cert` | No | Path to client certificate file for mTLS authentication |
| `client_key` | No | Path to client private key file for mTLS authentication |
| `request_template` | No | Base64-encoded JSON template for the request body |
| `response_template` | No | Base64-encoded JSON template for parsing the response |

**Note**: If `client_cert` is provided, `client_key` must also be provided (and vice versa).

### Default Request Format

If `request_template` is not specified, the default request format is:

```json
{"message":"{payload}"}
```

Where `{payload}` is replaced with the base64-encoded data to be signed.

### Default Response Format

If `response_template` is not specified, the default response format expected is:

```json
{"signature":"{signature}"}
```

Where `{signature}` contains the base64-encoded ECDSA signature.

## Template System

Templates use placeholders that are substituted at runtime:

### Request Template Placeholders
- `{payload}` - Replaced with the base64-encoded payload to sign

### Response Template Placeholders  
- `{signature}` - Indicates where to extract the base64-encoded signature from the response

### Custom Template Example

For a backend API that expects:
```json
{"data": "{payload}", "algorithm": "ES384"}
```

And returns:
```json
{"result": {"sig": "{signature}"}, "status": "ok"}
```

Encode the templates in base64:
- Request: `eyJkYXRhIjogIntwYXlsb2FkfSIsICJhbGdvcml0aG0iOiAiRVMzODQifQ==`
- Response: `eyJyZXN1bHQiOiB7InNpZyI6ICJ7c2lnbmF0dXJlfSJ9LCAic3RhdHVzIjogIm9rIn0=`

## Usage Examples

### Basic HTTP Signing

```bash
nitro-cli build-enclave \
  --docker-uri hello:latest \
  --output-file hello.eif \
  --signing-certificate cert.pem \
  --private-key "https://signing.example.com/v2/core/sign/ecdsa-sha256"
```

### With Mutual TLS (mTLS)

```bash
nitro-cli build-enclave \
  --docker-uri hello:latest \
  --output-file hello.eif \
  --signing-certificate cert.pem \
  --private-key "https://signing.example.com/v2/core/sign/ecdsa-sha256;client_cert=/path/to/client.crt;client_key=/path/to/client.key"
```

### With Custom Request/Response Templates

```bash
nitro-cli build-enclave \
  --docker-uri hello:latest \
  --output-file hello.eif \
  --signing-certificate cert.pem \
  --private-key "https://signing.example.com/sign;request_template=eyJkYXRhIjoie3BheWxvYWR9In0=;response_template=eyJzaWciOiJ7c2lnbmF0dXJlfSJ9"
```

### Sign Existing EIF with HTTP Signing

```bash
nitro-cli sign-eif \
  --eif-path image.eif \
  --signing-certificate cert.pem \
  --private-key "https://signing.example.com/v2/core/sign/ecdsa-sha256"
```

## Security Considerations

1. **HTTPS Required**: Only HTTPS URLs are supported to ensure transport security.

2. **Certificate Validation**: Server certificates are validated by default. The signing service must have a valid TLS certificate.

3. **mTLS Authentication**: For additional security, mTLS can be configured to authenticate the client to the signing service.

4. **Credential Protection**: Client private keys for mTLS should be protected with appropriate file permissions.

## Algorithm Support

The HTTP signing endpoint supports the following ECDSA algorithms:

| Algorithm | Description | COSE ID | Default |
|-----------|-------------|---------|---------|
| `ES384` | ECDSA with P-384 curve and SHA-384 | -35 | Yes |
| `ES512` | ECDSA with P-521 curve and SHA-512 | -37 | No |

The algorithm can be specified in the URL using the `algorithm` parameter. If not specified, ES384 is used by default.

### Example with ES512

```bash
nitro-cli build-enclave \
  --docker-uri hello:latest \
  --output-file hello.eif \
  --signing-certificate cert.pem \
  --private-key "https://signing.example.com/sign;algorithm=ES512"
```

### Endpoint Requirements

The signing endpoint should:

1. Accept the payload (PCR information serialized as CBOR)
2. Compute the appropriate hash of the payload (SHA-384 for ES384, SHA-512 for ES512)
3. Sign the hash using ECDSA with the corresponding curve (P-384 for ES384, P-521 for ES512)
4. Return the signature in DER or raw format

## Error Handling

The following errors may occur during HTTP signing:

| Error | Description |
|-------|-------------|
| `HttpSigningUrlParseError` | Invalid URL format or missing required parameters |
| `HttpSigningTlsError` | TLS/mTLS configuration error (e.g., invalid certificates) |
| `HttpSigningRequestError` | HTTP request failed (network error, timeout, etc.) |
| `HttpSigningResponseError` | Invalid response format or missing signature |
| `HttpSigningTemplateError` | Invalid template format or placeholder issues |

## Implementation Details

The HTTP signing feature is implemented in `src/http_signing.rs` and integrates with the existing signing flow. When a `--private-key` value starts with `https://`, it is treated as an HTTP signing URL instead of a file path or KMS ARN.

The signing flow:
1. Parse the HTTP signing URL and extract configuration
2. When signing is needed, serialize the PCR payload as CBOR
3. Base64-encode the payload and substitute into the request template
4. Send POST request to the signing endpoint
5. Parse the response using the response template to extract the signature
6. Construct the COSE signature structure with the obtained signature
