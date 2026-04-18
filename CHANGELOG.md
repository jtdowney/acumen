# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-04-18

### Fixed

- Synced internal `User-Agent` version constant with the package version; previously stuck at `1.0.0`

## [1.1.0] - 2026-04-18

### Changed

- Internal refactor of `link_header` to use `list.key_filter` from stdlib; now correctly handles repeated `rel` parameters in a single link
- Updated `gose` dependency to 2.1.0 and refreshed other dependencies

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

[1.1.1]: https://github.com/jtdowney/acumen/releases/tag/v1.1.1
[1.1.0]: https://github.com/jtdowney/acumen/releases/tag/v1.1.0
[1.0.0]: https://github.com/jtdowney/acumen/releases/tag/v1.0.0
