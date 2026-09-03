# Changelog

All notable changes to `voltcms/mcp` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Breaking
changes are permitted in `0.x` and are recorded here.

## [Unreleased]

### Added

- Repository scaffolding: `composer.json` (PHP `^8.2`, `mcp/sdk` `0.8.*`,
  `league/oauth2-server` `^9.4`, `voltcms/useraccess` `^2.0`), PHPUnit 11 configuration,
  GitHub Actions running the suite on PHP 8.2, 8.3 and 8.4, `.editorconfig`, `.gitignore`
  (excluding the signing-key directory), and the MIT licence.
- `README.md`, `SECURITY.md` and `CLAUDE.md`.
- `Configuration`: the explicit, immutable configuration object. It refuses to construct
  without an issuer URL and a resource URL rather than deriving either from a request header.
- Both spike-backed decision records under `docs/decisions/`.

[Unreleased]: https://github.com/voltcms/mcp/commits/main
