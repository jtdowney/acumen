# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-29

### Added

- Sans-IO ACME client implementing RFC 8555
- Account registration, updates, key rotation, and deactivation
- Order creation, polling, finalization, listing, and certificate retrieval
- Authorization fetching, challenge validation, and authorization deactivation
- Certificate revocation
- Renewal information fetching (ARI)
- JWS signing with JWK and KID-based headers
- Automatic `badNonce` retry with fresh nonce acquisition
- Erlang and JavaScript target support
- Integration test suite against Pebble

[1.0.0]: https://github.com/jtdowney/acumen/releases/tag/v1.0.0
