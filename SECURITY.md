# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.y   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

To report a security vulnerability, please use [GitHub Security Advisories](https://github.com/jtdowney/acumen/security/advisories/new).

**Please do not report security vulnerabilities through public GitHub issues.**

When reporting, include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

You can expect an initial response within 48 hours. We will work with you to understand the issue and coordinate disclosure.

## Security Model

acumen is an ACME client library (RFC 8555) that automates TLS certificate issuance. It uses a sans-IO architecture, the library builds HTTP request descriptions and parses responses but never performs network I/O. Callers provide a `send` function and control transport security.

All cryptographic operations (JWS signing, key thumbprints, CSR generation) are delegated to [gose](https://github.com/jtdowney/gose) and [kryptos](https://github.com/jtdowney/kryptos), which use platform-native implementations:

- **Erlang target**: OTP `:crypto` and `:public_key` modules (OpenSSL/LibreSSL)
- **JavaScript target**: Node.js `crypto` module (OpenSSL)

acumen does not implement any cryptographic primitives itself.

### Nonce Replay Protection

Every ACME request includes a server-provided nonce in the JWS protected header. The `execute` function manages nonce lifecycle automatically, extracting fresh nonces from response headers and retrying on `badNonce` errors (up to 3 attempts). Callers don't need to handle nonce state manually.

### Compile-Time Safety via Opaque Types

`UnregisteredKey` and `RegisteredKey` are distinct types. The type system enforces that account registration happens before any authenticated account operations. `UnregisteredKey` embeds the full public key in JWS headers; `RegisteredKey` uses the account URL (`kid`).

Each operation module exposes an opaque `RequestBuilder`. Callers configure it through setter functions and must call `build` with a valid `Context` and key to produce a request. Invalid configurations can't be constructed.

The opaque `Url` type prevents accidental URL manipulation or re-encoding that could break JWS signature verification.

### JWS Signing

acumen signs all ACME requests as JWS (JSON Web Signature) objects:

- Unregistered keys embed the full JWK in the protected header (used only for initial account registration)
- Registered keys use the account URL (`kid`) in the protected header for all subsequent operations
- Key rotation uses nested JWS, with the inner payload signed by the new key and the outer JWS signed by the old key, proving possession of both
- External Account Binding (EAB) uses HMAC-SHA-256 to bind an ACME account to an existing CA account

## Algorithm Support

### Signing Algorithms

| Algorithm       | Key Type | Status      |
| --------------- | -------- | ----------- |
| EdDSA (Ed25519) | OKP      | Recommended |
| ES256           | EC P-256 | Recommended |
| ES384           | EC P-384 | Recommended |
| ES512           | EC P-521 | Recommended |
| PS256           | RSA      | Supported   |

Note that only EC256 is required by the RFC to be supported. Not all ACME services support other JWK algorithms.

### Rejected

- Secp256k1 is explicitly rejected, not applicable to ACME
- Symmetric keys are not valid for ACME request signing (HMAC-SHA-256 is used only for EAB)

### CSR Hash Selection

Hash algorithms for Certificate Signing Requests are selected automatically based on key strength:

- EC P-256: SHA-256
- EC P-384: SHA-384
- EC P-521: SHA-512
- RSA < 3072 bits: SHA-256
- RSA 3072–4095 bits: SHA-384
- RSA 4096+ bits: SHA-512

## Application Responsibilities

acumen handles protocol-level security (nonce management, JWS signing, request construction) but does not manage the surrounding infrastructure. Applications integrating acumen must provide:

- Secure private key storage - acumen treats keys as values; persisting them securely is the caller's responsibility.
- Challenge deployment - Place HTTP-01 tokens, DNS-01 TXT records, or TLS-ALPN-01 certificates where the ACME server can reach them.
- TLS transport - All communication with the ACME server must use HTTPS; the caller's HTTP client handles certificate verification.
- Certificate lifecycle - Store issued certificates and schedule renewals before expiry.
