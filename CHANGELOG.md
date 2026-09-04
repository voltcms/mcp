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
- `Http\Request` and `Http\Response`: the value objects every handler takes and returns.
  `Request::fromGlobals()` is the whole integration for an application with no HTTP abstraction;
  `fromPsr7()` and `Response::toPsr7()` are there for one that has. The request deliberately
  carries no host — `$_SERVER['HTTP_HOST']` is attacker-controlled — and `Http\PsrAdapter` is the
  one place PSR-7 objects are built, for league's benefit.
- `Contracts\ConsentViewInterface` and `Contracts\LoginRedirectorInterface`: the two interfaces a
  consuming application implements. Neither is about security.
- `Contracts\IdentityProviderInterface` and `Contracts\ScopePolicyInterface`, with the
  `Identity\Identity` value object they speak in. The useraccess-backed implementations land in P5.
- `OAuth\Endpoints\AuthorizeEndpoint`: the S256-only guard, the login seam and the consent seam.
- `OAuth\Endpoints\TokenEndpoint` and `OAuth\Endpoints\RevokeEndpoint` (RFC 7009), over the
  shared `OAuth\Endpoints\Endpoint` base, which owns failure rendering and throttling.
- `OAuth\Consent\ConsentRequest` and `OAuth\Consent\ConsentTicketSigner`: the consent screen's
  input, and the signed ticket that binds an approval to the request it was shown for. See
  `docs/decisions/0003-consent-seam.md`.
- `OAuth\ResourceIndicator`: the RFC 8707 `resource` parameter, refused unless it names this
  server.
- `OAuth\Tokens\AccessTokenVerifier` and `OAuth\Tokens\AccessTokenClaims`: a bearer string
  turned back into claims, or into nothing. Accepts several public keys so a key rotation does not
  invalidate every live token at once.
- `EndpointUrls`, and the five endpoint URLs `Configuration` now exposes. They default to
  `<issuer>/oauth/…` and are validated by the same rules as the issuer.
- `RefreshTokenRepository::revokeForAccessToken()` and the shared `FileDbRepository::revokeWhere()`,
  so revoking either end of a grant revokes both.
- `lcobucci/jwt`, `php-http/discovery`, `psr/http-factory` and `psr/http-message` are now direct
  requirements. They were already installed transitively; this package calls them itself.
- `OAuthServer`: the façade. Five endpoints, six repositories, both league grants and a keypair,
  assembled from a `Configuration` and the two seams a consuming application fills.
- `OAuth\Keys\KeyManager`: RS256 generation on first use, a `0600` private key behind a deny-all
  `.htaccess`, RFC 7638 thumbprints as `kid`, rotation that keeps publishing the retired public key
  until the last token it signed has expired, and `purgeRetiredKeys()`. See
  `docs/decisions/0004-key-rotation.md`.
- `OAuth\Keys\JwksEndpoint`: the RFC 7517 key set `mcp/sdk`'s `JwksProvider` consumes.
- `OAuth\Endpoints\MetadataEndpoint`: the RFC 8414 authorization server metadata document league
  ships none of. `document()` returns it as an array for consumers rendering their own route.
- Every issued access token now carries the signing key's `kid` in its header, so a consumer can
  pick the right key out of a JWKS that is publishing more than one.
- `OAuthServer::purgeExpired()` sweeps codes, tokens and retired keys in one call, for the cron
  entry a flat-file deployment has to supply itself.

### Security

- Identifier lookups never delegate to `FileDB`'s search, which matches case-insensitively and
  treats `*` as a wildcard — a `client_id` of `claude*` would otherwise resolve a stored
  `claude-desktop`.
- PKCE with `S256` is required of every client, confidential ones included, and the check runs
  before league sees the request. league registers a `PlainVerifier` alongside the `S256Verifier`
  and defaults an absent `code_challenge_method` to `plain`; a `plain` challenge was accepted in
  the spike.
- A `resource` parameter naming another server is refused with `invalid_target` rather than
  answered with a token for this one.
- Consent approvals are bound to the user, client, redirect URI, scopes, code challenge and state
  they were shown for, so a cross-site POST cannot approve an authorization request.
- Revocation answers 200 for a token belonging to another client instead of refusing, so the
  endpoint cannot be used to ask whether a token exists.
- No endpoint lets an internal exception message reach a client: anything that is not an
  `OAuthServerException` becomes a fixed `server_error`.

[Unreleased]: https://github.com/voltcms/mcp/commits/main
