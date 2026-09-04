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
- The six OAuth entities: `Client`, `Scope`, `AuthCode`, `RefreshToken`, `User` and
  `ResourceBoundAccessToken`.
- `ResourceBoundAccessToken` binds the access token's `aud` claim to the configured resource
  rather than the client id (RFC 8707), keeps the client as a `client_id` claim (RFC 9068) and
  adds the `iss` claim league does not set. It implements `AccessTokenEntityInterface` directly
  because league's `AccessTokenTrait` hard-codes the client as the audience and cannot be
  extended.
- `Client::supportsGrantType()` answers from the client's registered grant types instead of
  league's trait, which returns `true` for every grant.
- The five OAuth repositories over `FileDB` — client, access token, auth code, refresh token
  and scope — with a shared `FileDbRepository` base: identifier lookups compared with
  `hash_equals()`, mutations inside `Lock::exclusive()`, an absent or expired record reading as
  revoked, duplicate identifiers refused, optional `AuditLog` records for every issuance and
  revocation, and `purgeExpired()` for deployments that want to sweep.
- Client secrets are stored only as hashes, and only for confidential clients.

### Security

- Identifier lookups never delegate to `FileDB`'s search, which matches case-insensitively and
  treats `*` as a wildcard — a `client_id` of `claude*` would otherwise resolve a stored
  `claude-desktop`.

[Unreleased]: https://github.com/voltcms/mcp/commits/main
