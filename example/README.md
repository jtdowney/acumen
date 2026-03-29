# ACME Example

A complete ACME client demonstrating the acumen library. It registers an account,
creates an order, completes challenges (HTTP-01, DNS-01, DNS-Account-01, or
DNS-Persist-01), and obtains a TLS certificate with automatic renewal.

## Prerequisites

- [Gleam](https://gleam.run) >= 1.14
- Erlang/OTP >= 27

## Running

Run the example from the `example/` directory:

```sh
cd example
gleam run -- --domain example.com --email you@example.com
```

## CLI options

| Option             | Default               | Description                                                             |
| ------------------ | --------------------- | ----------------------------------------------------------------------- |
| `--domain`         | _(required)_          | Domain name for the certificate                                         |
| `--email`          | _(required)_          | Contact email for the ACME account                                      |
| `--directory`      | Let's Encrypt staging | ACME directory URL                                                      |
| `--http-port`      | `80`                  | Port for the HTTP-01 challenge server                                   |
| `--https-port`     | `443`                 | Port for the TLS server                                                 |
| `--storage-path`   | `priv/storage`        | Directory for persistent account/order data                             |
| `--cert-path`      | `priv/cert.pem`       | Output path for the certificate chain                                   |
| `--key-path`       | `priv/key.pem`        | Output path for the certificate private key                             |
| `--profile`        | _(none)_              | Certificate profile to request                                          |
| `--challenge-type` | `http-01`             | Challenge type: `http-01`, `dns-01`, `dns-account-01`, `dns-persist-01` |
| `--eab-key-id`     | _(none)_              | EAB key ID from the CA (requires `--eab-mac-key`)                       |
| `--eab-mac-key`    | _(none)_              | EAB MAC key, base64url-encoded (requires `--eab-key-id`)                |

## Architecture

The example runs three supervised services:

- Challenge store: an OTP actor that holds pending challenge tokens
- HTTP server: a Wisp/Mist server that responds to `/.well-known/acme-challenge/` requests
- Renewal manager: handles initial certificate issuance and periodic renewal using ACME Renewal Information (ARI)

Supporting modules:

- Storage: persists account keys and renewal scheduling data to disk so the application can resume without re-registering on restart
- Certificate: PEM parsing and certificate inspection helpers
- ACME client: configuration types and the core ACME workflow (directory fetch, account registration, order creation, challenge completion, finalization)
