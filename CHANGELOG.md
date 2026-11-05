# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- MIT licence.
- Dependabot configuration for GitHub Actions and Go modules.
- This changelog.

### Changed

- Minimum Go version is now 1.26 (`go 1.26` in `go.mod`); Go 1.24 is out of support.
- CI tests on Go 1.26 and 1.27 and uses `actions/checkout` v7 and `actions/setup-go` v7.

## [0.1.0] - 2026-07-26

### Added

- `pev seal`: hash every artefact in a capture directory and write `manifest.json`.
- `pev stamp`: request an RFC 3161 trusted timestamp over the manifest and verify the
  returned token against the request (digest and nonce) before storing it.
- `pev verify`: offline verification of a bundle (directory or zip): manifest schema,
  per-artefact size and SHA-256, no unlisted content, TSTInfo imprint, CMS signature,
  ESS signingCertificate, timestamping EKU, certificate validity at genTime and an
  optional chain to `-tsa-roots`; human-readable or `-json` report.
- `pev inspect`: print what a bundle claims without verifying it.
- Stdlib-only RFC 3161 / CMS implementation in `internal/rfc3161`.
- Example bundles (one intact, one tampered) verified in CI, and the bundle format
  specification in `docs/bundle-format.md`.

[Unreleased]: https://github.com/moveeeax/page-evidence-api/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/moveeeax/page-evidence-api/releases/tag/v0.1.0
