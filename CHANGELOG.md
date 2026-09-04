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
- `Identity\UserAccessIdentityProvider`: identity over `voltcms/useraccess`, concrete, so a
  consumer using it implements no identity code at all. Group membership is computed against the
  injected group provider rather than through `User::isMemberOf()`, which reaches for a singleton.
- `Identity\ScopePolicy`: the role-to-scope table, with `everyoneMay()` for the single-account
  case.
- `Identity\UserAccessSession` and `Contracts\SessionInterface`: "who is logged in", isolated so
  that starting a PHP session — the one thing in this package that writes a header — happens in
  one place and lazily.
- `Bridge\McpTokenValidator`: `mcp/sdk`'s bearer-token seam answered with the tokens league
  minted. No network, no `firebase/php-jwt`, and the account and its scopes re-read on every
  request.
- `Bridge\ProtectedResourceMetadata` and `Bridge\SessionStoreFactory`: the RFC 9728 document,
  and the handshake-era session store kept under the configured storage directory with a `purge()`
  for the same cron entry.
- `McpServer`: the MCP endpoint. Registers tools, serves both protocol eras through
  `mcp/sdk`'s transport, and refuses anything without a valid token before a JSON-RPC envelope is
  parsed. `DnsRebindingProtectionMiddleware` is rebuilt around the configured resource host, whose
  localhost-only default would otherwise 403 every request to a deployed server.
- `Http\Request::$rawBody`: the body as it arrived. MCP posts `application/json`, which PHP never
  puts in `$_POST`, so a request object carrying only the parsed form could not reach the SDK.
- Client ID Metadata Documents, on by default: a `client_id` that is an https URL is resolved by
  fetching the document there, so a client this server has never met needs no registration.
  `OAuth\Clients\ClientIdMetadataDocument` validates it, `ClientIdMetadataResolver` fetches and
  caches it, `SsrfGuard` decides whether the URL may be fetched at all, and
  `StreamClientIdMetadataFetcher` is the default transport. See
  `docs/decisions/0006-who-answers-registration.md`.
- `OAuth\Clients\ManualRegistration`: registering a client from a script, which for most
  deployments is the only registration there is. It generates the identifier and, for a confidential
  client, the secret — returned once, stored only as a hash.
- `OAuth\Endpoints\RegisterEndpoint`: RFC 7591 dynamic registration, **off unless a deployment asks
  for it** with `EndpointUrls::below(..., withRegistration: true)`. `mcp/sdk` also ships a
  registration middleware; it is deliberately not installed.
- `OAuthServer::register()`, `registrations()` and `clientMetadata()`.
- `FileDbRepository::upsert()`, for caches, where writing over the previous entry is the point.
- `examples/blog/`: the whole flow — three tools, a consent page, a login page, one front
  controller, a cron entry and a registration script.
- `OAuth\WellKnownPath`: where a metadata document belongs, given the identifier it describes.
  RFC 8414 §3.1 and RFC 9728 §3.1 insert the well-known segment between the host and the path, so a
  resource of `https://example.com/mcp` publishes at
  `/.well-known/oauth-protected-resource/mcp` — not the bare path, which is all this server served
  before. A conforming client got a 404 at the first hop of discovery.
- `McpServer::resourceMetadataPaths()` and `OAuthServer::metadataPaths()`: the façades say where
  their documents belong, so a front controller asks rather than hard-coding a constant that is only
  right for a path-less identifier.
- `MetadataEndpoint::paths()`, and `Bridge\ProtectedResourceMetadata::pathsFor()`.
- `docs/release-checklist.md`: the runbook for the live pass before `0.1.0`.
- `examples/blog/bin/create-user.php` and `examples/blog/dev-router.php`, because the example's own
  README told you to do two things you could not: create an account with tooling `voltcms/useraccess`
  does not ship, and run it under a built-in server that routes neither `/.well-known/…` nor
  `/oauth/…`.

### Changed

- The RFC 8414 and RFC 9728 metadata documents are now served at the path-inserted URLs their specs
  name, with the bare well-known path kept as a fallback. `McpServer::resourceMetadataPath()` returns
  the inserted URL, which is also what the `WWW-Authenticate` challenge advertises — a consumer
  routing that document from a hard-coded constant must switch to `resourceMetadataPaths()`.
- The example reads `MCP_ISSUER`, `MCP_RESOURCE` and `MCP_STORAGE` from the environment instead of
  having them edited into `bootstrap.php`.
- `EndpointUrls::below()` no longer gives registration a URL unless asked. A server that has not
  opted in leaves `Configuration::$registrationEndpoint` null, does not advertise
  `registration_endpoint` in its RFC 8414 metadata, and answers `OAuthServer::register()` with 404.

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
- **Access-token revocation is now immediate.** Validation reads the token store on every request;
  the cost was measured before it was accepted. `SECURITY.md`'s "not instant" caveat is replaced by
  a narrower one. See `docs/decisions/0005-validation-reads-the-store.md`.
- A token's scopes are narrowed on every validation to what the account's roles currently grant, so
  a demotion takes effect before the token expires.
- `UserAccessIdentityProvider` validates an identifier's shape before it reaches the store — which
  builds a filesystem path out of it — and re-checks it with `hash_equals()` afterwards, because
  the store lowercases before looking up.
- Every refusal from `McpTokenValidator` returns the same description, so a caller cannot tell
  "expired" from "revoked" from "no such account".
- Client metadata fetches are guarded against server-side request forgery: HTTPS on the default
  port only, no redirects, and every address the host resolves to checked against the private,
  loopback, link-local and reserved ranges — because `metadata.attacker.example` resolving to
  `169.254.169.254` is the attack, and no hostname filter catches it. `ext-curl`, when present,
  pins the connection to the approved address so DNS is resolved once.
- Both successes and refusals are cached, so a `client_id` naming somebody else's URL cannot turn
  this server into an amplifier.
- A client metadata document must claim the URL it was served from, or an attacker's document could
  name itself Claude on a user's consent screen.
- A stored client record wins over a metadata document at the same identifier, so deactivating a
  client is final.
- Dynamic client registration is opt-in, and nothing advertises a registration endpoint that is not
  configured.
- `ScopeRepository::finalizeScopes()` now applies the scope policy, which closes the gap its own
  docblock flagged in P2. The authorize endpoint narrows before consent and so covers the
  authorization-code flow; the refresh flow has no consent screen, so a user demoted after
  consenting would otherwise have kept their old scopes for as long as they kept refreshing. A
  refresh by an account that is gone, or that grants none of the token's scopes, is now
  `invalid_grant`.
- Key files are created with `fopen(..., 'x')` and `chmod`'d before a byte is written, rather than
  written and narrowed afterwards. The old order left a window — short, and on a shared host long
  enough — in which the private key was readable. league's own key-permission check is left enabled
  as a second pair of eyes.

[Unreleased]: https://github.com/voltcms/mcp/commits/main
