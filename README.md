# acumen

[![Package Version](https://img.shields.io/hexpm/v/acumen)](https://hex.pm/packages/acumen)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/acumen/)

Acumen is a Gleam library for interacting with [Automatic Certificate Management Environment (ACME)](https://tools.ietf.org/html/rfc8555) servers like [Let's Encrypt](https://letsencrypt.org). It handles account registration, domain challenges, and TLS certificate issuance.

## Features

- Uses a sans-IO pattern - produces HTTP request descriptions and consumes responses rather than performing I/O directly
- HTTP client agnostic - use any HTTP library (`gleam_httpc`, `gleam_fetch`, etc.)
- Works on both Erlang and JavaScript targets
- Supports ACME Renewal Information (ARI) per [RFC 9773](https://tools.ietf.org/html/rfc9773) for server-suggested renewal windows
- Tested against [Pebble](https://github.com/letsencrypt/pebble)

## Installation

```sh
gleam add acumen
```

You will also need an HTTP client library to send the requests that acumen builds. For Erlang targets, [`gleam_httpc`](https://hex.pm/packages/gleam_httpc) is a good choice. For JavaScript targets, [`gleam_fetch`](https://hex.pm/packages/gleam_fetch) works well.

## Examples

Acumen follows a build -> send -> parse pattern for every operation. The `acumen.execute` function orchestrates this loop and handles automatic `badNonce` retry.

### Fetching the directory and initial nonce

Before any ACME operation, you need to fetch the server directory and an initial replay nonce.

```gleam
import acumen
import acumen/nonce
import gleam/http/request
import gleam/httpc

// Fetch the ACME directory
let assert Ok(req) = request.to("https://acme-staging-v02.api.letsencrypt.org/directory")
let assert Ok(resp) = httpc.send(req)
let assert Ok(directory) = acumen.directory(resp)

// Get an initial nonce
let assert Ok(nonce_req) = nonce.build(directory)
let assert Ok(nonce_resp) = httpc.send(nonce_req)
let assert Ok(initial_nonce) = nonce.response(nonce_resp)

// Create context for subsequent requests
let ctx = acumen.Context(directory:, nonce: initial_nonce)
```

### Registering an account

Generate a key and register an account with the ACME server.

```gleam
import acumen/register_account
import gose/jwk
import kryptos/ec

// Generate an account key
let key = jwk.generate_ec(ec.P256)
let unregistered = acumen.UnregisteredKey(key)

// Build and submit the registration
let reg = register_account.request()
  |> register_account.contacts(["mailto:admin@example.com"])
  |> register_account.agree_to_terms

let assert Ok(#(resp, ctx)) = acumen.execute(
  ctx,
  build: register_account.build(reg, _, unregistered),
  send: httpc.send,
)

let assert Ok(#(account, registered_key)) =
  register_account.response(resp, unregistered)
```

From here on, use `registered_key` for all subsequent operations.

### Creating an order

Create an order for the domains you want a certificate for.

```gleam
import acumen/create_order

// Identifiers can be DNS names or IP addresses
let assert Ok(order_req) = create_order.request(
  identifiers: [acumen.DnsIdentifier("example.com"), acumen.DnsIdentifier("www.example.com")],
)
// For IP certificates: acumen.IpIdentifier("192.0.2.1")

let assert Ok(#(resp, ctx)) = acumen.execute(
  ctx,
  build: create_order.build(order_req, _, registered_key),
  send: httpc.send,
)

let assert Ok(ord) = create_order.response(resp)
```

### Completing challenges

For each authorization in the order, fetch it and complete the appropriate challenge.

```gleam
import acumen/challenge
import acumen/fetch_authorization
import acumen/validate_challenge
import gleam/list

let assert [auth_url, ..] = ord.authorizations

// Fetch the authorization
let assert Ok(#(resp, ctx)) = acumen.execute(
  ctx,
  build: fetch_authorization.build(auth_url, _, registered_key),
  send: httpc.send,
)

let assert Ok(auth) = fetch_authorization.response(resp, auth_url)

// Find the HTTP-01 challenge
let assert Ok(http_challenge) =
  challenge.find_by_type(auth.challenges, of: challenge.Http01)

// Compute the key authorization value
let assert Ok(key_auth) = challenge.key_authorization(http_challenge, registered_key)
let assert Ok(token) = challenge.token(http_challenge)
// Deploy: GET /.well-known/acme-challenge/{token} -> key_auth

// Tell the server to validate
let assert Ok(#(resp, ctx)) = acumen.execute(
  ctx,
  build: validate_challenge.build(challenge.url(http_challenge), _, registered_key),
  send: httpc.send,
)

let assert Ok(validated_challenge) = validate_challenge.response(resp)
```

### Finalizing the order

Once all challenges are validated, generate a CSR and finalize the order.

```gleam
import acumen/finalize_order
import acumen/order
import kryptos/ec

// Generate a certificate key pair and CSR from the order
// Use order.to_rsa_csr(ord, rsa_key) for RSA keys
let #(cert_key, _pub) = ec.generate_key_pair(ec.P256)
let assert Ok(csr) = order.to_ec_csr(ord, cert_key)

// Finalize the order
let assert Ok(#(resp, ctx)) = acumen.execute(
  ctx,
  build: finalize_order.build(ord.finalize_url, _, registered_key, csr:),
  send: httpc.send,
)

let assert Ok(finalized_order) = finalize_order.response(resp, ord.url)
```

### Fetching the certificate

After the order is finalized, poll until the order reaches the `Valid` status, then download the certificate.

```gleam
import acumen/fetch_certificate
import acumen/fetch_order
import acumen/order
import gleam/erlang/process

// Poll until the order is valid
let assert Ok(#(resp, ctx)) = acumen.execute(
  ctx,
  build: fetch_order.build(ord.url, _, registered_key),
  send: httpc.send,
)

let assert Ok(completed_order) = fetch_order.response(resp, ord.url)

// The certificate URL is inside the Valid status variant
let assert order.Valid(cert_url) = completed_order.status

// Download the certificate chain (PEM format)
let assert Ok(#(resp, ctx)) = acumen.execute(
  ctx,
  build: fetch_certificate.build(cert_url, _, registered_key),
  send: httpc.send,
)

let assert Ok(pem_chain) = fetch_certificate.response(resp)
// pem_chain contains the full certificate chain in PEM format
```

If the order is still processing, use `acumen.retry_after(resp)` to determine how long to wait before polling again.

### Error handling

All operations return `Result` types. When using `acumen.execute`, errors are wrapped in `ExecuteError`:

- `ProtocolError(error: acme_error, context: context)` — the ACME server returned an error with updated context (see `AcmeError` for all variants)
- `TransportError(e)` — your HTTP client returned an error
- `NonceRetryExhausted` — automatic `badNonce` retry failed after 4 attempts

### Other challenge types

Acumen supports multiple challenge types beyond HTTP-01:

- DNS-01: Use `challenge.dns01_txt_record(key_auth)` to compute the TXT record value for `_acme-challenge.<domain>`
- DNS-Account-01: Use `challenge.dns_account01_txt_record(for: domain, account_url: kid, key_authorization: key_auth)` for account-bound DNS challenges — returns `Result(#(record_name, record_value), AcmeError)`
- TLS-ALPN-01: Parsed and decoded; the caller must handle serving the `acme-tls/1` ALPN certificate with the acmeIdentifier extension
- DNS-Persist-01: Use `challenge.dns_persist01_txt_record(issuer: issuer_name, account_url: kid)` for persistent DNS challenges
