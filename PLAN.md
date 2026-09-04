# voltcms/mcp — plan for a drop-in MCP server package for flat-file PHP applications

**Drop this file into `voltcms/mcp`** as `PLAN.md`, with §9 split out as `CLAUDE.md` and the
two decision records copied into `docs/decisions/`. It is self-contained: nothing here
requires access to the markdown-editor repository it came from.

> **Two spikes cut this plan down before any code was written.**
> `MCP_DECISION_0001_build_vs_adopt.md` adopted `mcp/sdk` for the protocol, deleting the
> transport, JSON-RPC and tool layers. `MCP_DECISION_0002_wrap_or_write.md` wrapped
> `league/oauth2-server` for issuance and found that `voltcms/useraccess` already ships the
> store, the lock, the throttle, the audit log and the identity model. What is left is the
> glue nobody else has — and the estimate went from 18–22 days to **4–7**.

---

## 1. What this package is

`voltcms/mcp` makes a flat-file PHP application speak MCP to a remote client — a Claude
session, a ChatGPT session, Claude Code — with real OAuth, no identity provider, no database
and no daemon.

It composes four things and adds the piece nobody else has:

| Layer | Provided by | |
|---|---|---|
| MCP protocol, both eras, HTTP transport, tools | **`mcp/sdk`** | official, Symfony + PHP Foundation |
| Token issuance: codes, PKCE, refresh rotation | **`league/oauth2-server`** | mature, widely deployed |
| Users, groups, sessions, flat-file store, locking, throttle, audit | **`voltcms/useraccess`** | already in the family |
| **Everything between them** | **`voltcms/mcp`** | the reason this repo exists |

That last row is: FileDB-backed OAuth repositories, S256-only and RFC 8707 tightenings over
league, RFC 8414 metadata, the consent seam, Client ID Metadata Documents, signing-key
management, and the bridge that hands `mcp/sdk` a validator for the tokens league minted.

A consuming application supplies its tools, its consent markup and its content directories.
Nothing else.

### 1.1 Why the gap exists

`mcp/sdk` closed it deliberately. Its ADR `0001-oauth-authorization-server-out-of-scope.md`
declines authorization-server pull requests on sight:

> The SDK will NOT implement an authorization server: no token issuance, no token signing or
> key management, no login UI, no consent UI, no authorization-code or refresh-token storage.

Its answer is "use an external IdP, or `league/oauth2-server` in your own application". For a
personal blog on shared hosting, the first is absurd and the second is 180 lines of
repositories plus two security tightenings that are easy to get wrong. This package is those
180 lines, written once, tested, and shared.

---

## 2. Package identity

| | |
|---|---|
| Repository | `voltcms/mcp` |
| Composer package | `voltcms/mcp` |
| Namespace | `VoltCMS\MCP\` |
| PHP | `^8.2` |
| Requires | `mcp/sdk` (pinned `0.8.*`), `league/oauth2-server ^9.4`, `voltcms/useraccess`, `lcobucci/jwt`, `php-http/discovery`, `psr/http-factory`, `psr/http-message`, `ext-json`, `ext-openssl` |
| Suggests | a PSR-17 implementation (`nyholm/psr7` recommended) — discovered at runtime, and needed by `mcp/sdk`'s HTTP transport anyway |
| License | MIT |
| Versioning | Semver from `0.1.0`; breaking changes allowed in `0.x` and recorded in `CHANGELOG.md` |

On the `voltcms/useraccess` constraint: the first consumer pins `2.0.2` exactly. This package
should express the range it actually tests against (`^2.0`) rather than inheriting that pin by
accident — decision 0002, open question 4.

---

## 3. Architecture

```
src/
    McpServer.php                  # façade: build mcp/sdk's server, return a PSR-7 response
    OAuthServer.php                # façade: authorize / token / revoke / register / metadata
    Configuration.php              # issuer URL, TTLs, key paths, scopes — all explicit

    OAuth/
        Repositories/              # the 180 lines decision 0002 measured
            ClientRepository.php
            AccessTokenRepository.php
            AuthCodeRepository.php
            RefreshTokenRepository.php
            ScopeRepository.php
            FileDbRepository.php   # shared find/put/revoke over VoltCMS\FileDB\FileDB
        Entities/
            Client.php  Scope.php  AuthCode.php  RefreshToken.php  User.php
            ResourceBoundAccessToken.php   # NOT AccessTokenTrait — see §4.2
        Endpoints/
            AuthorizeEndpoint.php  # S256-only guard, consent seam, login redirection
            TokenEndpoint.php
            RevokeEndpoint.php     # RFC 7009
            RegisterEndpoint.php   # RFC 7591, if we answer it at all (§4.4)
            MetadataEndpoint.php   # RFC 8414 — league ships none
        Keys/
            KeyManager.php         # generate, store 0600 outside the web root, rotate
            JwksEndpoint.php       # publishes what mcp/sdk's JwksProvider consumes
        Clients/
            ClientIdMetadataDocument.php   # CIMD fetch, cache, validation
            ManualRegistration.php

    Identity/
        UserAccessIdentityProvider.php     # CONCRETE: UserProvider + GroupProvider + SessionAuth
        Identity.php                       # id, displayName, roles
        ScopePolicy.php                    # roles -> grantable scopes

    Bridge/
        McpTokenValidator.php      # mcp/sdk's AuthorizationTokenValidatorInterface
        ProtectedResourceMetadata.php      # feeds the SDK's RFC 9728 handler
        SessionStoreFactory.php    # mcp/sdk's FileSessionStore, for legacy-era clients

    Contracts/
        ConsentViewInterface.php   # the consumer's markup, the consumer's stylesheet
        LoginRedirectorInterface.php
        IdentityProviderInterface.php      # UserAccessIdentityProvider implements it
        ScopePolicyInterface.php

    Http/
        Request.php  Response.php  # fromGlobals() / fromPsr7(); every handler RETURNS one
```

There is no `Storage/` and no `Support/`. `voltcms/useraccess` is both: `FileDB` is the store,
`Lock` the mutex, `AuditLog` the audit sink, `LoginThrottle` the throttle.

### 3.1 What a consumer implements

Two interfaces, and neither is about security:

```php
interface ConsentViewInterface
{
    /** Render the consent page. Your markup, your stylesheet, your language. */
    public function render(ConsentRequest $request): Response;
}

interface LoginRedirectorInterface
{
    /**
     * Send an unauthenticated visitor to your own login page and come back.
     *
     * You are responsible for preserving the pending request across the round trip. A login
     * flow that redirects to the current path WITHOUT its query string will silently discard
     * the entire authorization request — client_id, redirect_uri, state, code_challenge and
     * all. That is not hypothetical: it is finding F1 in the first consuming application.
     */
    public function redirectToLogin(Request $request): Response;
}
```

Identity is *not* on that list: `UserAccessIdentityProvider` is concrete, and a consumer using
`voltcms/useraccess` passes its `users/` and `groups/` directories rather than writing an
adapter. `IdentityProviderInterface` exists for applications with a different user store.

---

## 4. What this package adds over its dependencies

Everything here is a finding from decision 0002's spike, not speculation.

### 4.1 S256-only, enforced before league sees the request

`AuthCodeGrant::__construct()` registers a `PlainVerifier` alongside the `S256Verifier`;
`private array $codeChallengeVerifiers` is unreachable from a subclass, and the only
PKCE-related public method *weakens* the requirement. The spike confirmed a `plain` challenge
is accepted.

`AuthorizeEndpoint` therefore rejects any `code_challenge_method` other than `S256` before
delegating. **This needs a test that fails loudly**, because a league upgrade that changed the
constructor would otherwise silently re-open `plain`.

### 4.2 RFC 8707 audience binding

league's JWT carries `aud = <client id>` (observed: `aud, jti, iat, nbf, exp, sub, scopes`,
RS256). The MCP spec wants the audience to be the **resource** — the endpoint's canonical URL
— so a token minted for one server cannot be replayed at another.
`AccessTokenTrait::convertToJWT()` is `private`, so `ResourceBoundAccessToken` implements
`AccessTokenEntityInterface` directly and builds the JWT with `lcobucci/jwt` (already a league
dependency), adding the resource. About forty lines, and the second upgrade tripwire.

### 4.3 The issuer URL is configuration, never a header

`$_SERVER['HTTP_HOST']` is attacker-controlled. If metadata or an audience were derived from
it, a forged `Host` would publish an attacker's origin as the authorization server.
`Configuration` **refuses to construct** without an explicit issuer URL rather than guessing
one.

### 4.4 RFC 8414 metadata, and who answers DCR

league ships no authorization-server metadata document (verified); `MetadataEndpoint` is ours.
`mcp/sdk` *does* ship DCR middleware and so might we — exactly one must answer, and
2026-07-28 prefers Client ID Metadata Documents over DCR anyway. Resolve at integration time
and write it down.

### 4.5 The FileDB constraint, documented not hidden

`FileDB::create()` always generates its own UUID, so an OAuth identifier cannot be the
document id; records carry it in an `oauth_id` field and lookups are `readAll()` plus a scan —
**O(n) per token validation**, with the record id under `_id`, not `id`. Irrelevant at
personal-blog scale, a documented ceiling as a library. If it ever bites, a purpose-built
store replaces FileDB for that one collection.

### 4.6 Key management

The token format is now JWT, so this is real work the opaque design avoided: generate an RS256
keypair, store the private key outside the web root at `0600`, rotate it, publish JWKS.
`mcp/sdk`'s `JwksProvider` and `JwtTokenValidator` consume the other end. `KeyManager` owns
generation and rotation so no consumer has to.

### 4.7 What league already gets right — and we must not undo

Verified working in the spike, and covered by tests here so an upgrade cannot regress them
silently: PKCE required for public clients; authorization codes single-use (replay refused);
refresh tokens rotated on use; `redirect_uri` matched exactly (a foreign URI is refused).

### 4.8 FileDB's search must never resolve an identifier — a third tripwire

Found in P2, not in the spikes, and it is the sharpest edge in the store.
`FileDB::read(null, ['oauth_id' => …])` does not compare for equality. Its matcher is
`strcasecmp()`, and it treats `*` as a wildcard. Measured on 2.0.2, against a stored
`claude-desktop`:

| lookup | result |
|---|---|
| `claude-desktop` | matches |
| `claude*` | **matches** |
| `*desktop` | **matches** |
| `CLAUDE-DESKTOP` | **matches** |

Client ids and token identifiers arrive straight out of an HTTP request, so delegating the
comparison would hand an attacker prefix matching over the credential store — `client_id=a*`
resolving whichever client happens to sort first — and would drop roughly a bit of entropy per
alphabetic character of every token identifier it ever compared.

`FileDbRepository::find()` therefore scans `readAll()` itself and compares with `hash_equals()`.
That costs nothing extra: §4.5 already established every lookup is a scan. The tests in
`FileDbRepositoryTest` and the `client_id=claude*` case in `AuthorizationFlowTest` are the
tripwire — if they ever start failing, something has begun delegating to FileDB's search again.

---

## 5. Security posture, stated plainly

- **Access tokens are JWTs with a one-hour TTL.** They are self-contained and readable by
  anyone holding one, and revoking an access token before it expires is not instant unless a
  store lookup runs on every request. Revoking the **grant** kills the refresh path
  immediately, which is the control that matters. `SECURITY.md` says this in these words
  rather than implying instant revocation.
- **Scopes are re-checked against the live user record on every validation.** A deactivated
  account or a removed role invalidates a live token now, not at expiry. This is
  `UserAccessIdentityProvider`'s job and it is the reason `findUser()` exists separately from
  `currentUser()`.
- A token can never carry a scope its granting user's roles do not support (`ScopePolicy`).
- Throttling on authorize, token and register via `LoginThrottle`, keyed by identifier + IP.
- Every issuance, refresh and revocation goes to `AuditLog`.
- CIMD fetches: HTTPS only, no cross-host redirects, no private or link-local addresses, a
  size cap, a cached TTL, and a timeout under the ~30 s a shared host allows.
- Stores belong **outside the web root**. `DirectoryGuard`-style deny-all files are defence in
  depth for hosts where that is impossible, and the README says which is which.

---

## 6. Testing

PHPUnit 11, mirroring `src/`. `assertSame`. One explicit test per case, no data providers.
Temp directories through a shared helper. **CI on PHP 8.2, 8.3 and 8.4 from the first
commit** — this is credential issuance.

- **The two tripwires**, first and loudest: a `plain` code challenge is refused end to end;
  an issued access token's `aud` is the resource URL, not the client id. Both must fail
  visibly if a dependency upgrade changes behaviour underneath.
- **Inherited guarantees**, tested here even though league implements them, because we are
  the ones who promise them: PKCE required for public clients; code single-use and TTL;
  refresh rotation; exact `redirect_uri` match including near misses (trailing slash, added
  query, case).
- **Repositories**: revoke and is-revoked round-trips; a missing record reads as revoked, not
  as valid; concurrent refresh under `Lock` produces one winner.
- **Identity**: role → scope mapping; a user deactivated or demoted **after** issue fails
  validation; scopes never exceed the policy.
- **Metadata**: the RFC 8414 document is byte-stable and contains no header-derived value.
- **Keys**: generation produces a `0600` private key; rotation keeps the previous public key
  in JWKS until its tokens expire.
- **Bridge**: `McpTokenValidator` returns the SDK's `AuthorizationResult` shapes for valid,
  expired, wrong-audience and insufficient-scope tokens.

**No network, ever.** The CIMD fetcher is injected and stubbed.

---

## 7. Repository scaffolding

- [x] `composer.json` — MIT, `php: ^8.2`, the four requires of §2, `suggest: nyholm/psr7`
- [x] `phpunit.xml`; `.github/workflows/test.yml` on 8.2/8.3/8.4; `.editorconfig`
- [x] `README.md` — the pitch, install, a worked example, the `.well-known` snippets for
      Apache and nginx, and an honest "when to use an external IdP instead"
- [x] `SECURITY.md` — §5 as guarantees, the JWT revocation caveat in plain words, disclosure
      address
- [x] `CHANGELOG.md`, `LICENSE`, `CLAUDE.md` (§9)
- [x] `docs/decisions/0001-build-vs-adopt.md`, `0002-wrap-or-write.md` — copied in
- [ ] `examples/blog/` — the full flow: tools, consent page, `.well-known`, end to end
- [x] `.gitignore` — `/vendor/`, `.phpunit.result.cache`, and **the key directory**

---

## 8. Delivery phases

| Phase | Content | Rough size |
|---|---|---|
| **P0 — spikes** | ✅ Done — decisions 0001 and 0002. | — |
| **P1 — scaffolding** | ✅ Done. Repo, composer, PHPUnit, CI, license, README skeleton, both decision records. | 0.5 day |
| **P2 — OAuth repositories** | ✅ Done. The five repositories and six entities over `FileDB`, with `Lock` around mutations. The spike's 180 lines, made production-shaped and tested. | 1 day |
| **P3 — the tightenings** | ✅ Done. `AuthorizeEndpoint` with the S256-only guard and the consent seam; `ResourceBoundAccessToken`; `TokenEndpoint`; `RevokeEndpoint`. Both tripwire tests. | 1–1.5 days |
| **P4 — metadata & keys** | ✅ Done. RFC 8414 document, `KeyManager`, JWKS endpoint, and the `OAuthServer` façade that assembles them. **First usable release.** | 1 day |
| **P5 — identity & bridge** | `UserAccessIdentityProvider`, `ScopePolicy`, `McpTokenValidator`, `ProtectedResourceMetadata`, `SessionStoreFactory`, `McpServer` façade. | 1 day |
| **P6 — clients & polish** | CIMD with its SSRF guards, manual registration, the DCR question (§4.4), the example, an end-to-end pass with MCP Inspector and Claude Code, tag `0.1.0`. | 1–1.5 days |

**≈ 4–7 focused days.** The consuming application works against a `path` repository from P4.

---

## 9. Coding standards (the `CLAUDE.md` seed)

- PSR-4, one class per file, `declare(strict_types=1)` in every file.
- Methods and properties `camelCase`; class constants `SCREAMING_SNAKE` with explicit
  visibility, declared at the top of the class.
- No global constants, no `global`/`$GLOBALS` — state arrives through the constructor.
- Every parameter, return and property typed.
- Allman braces for class and function declarations, K&R for control flow.
- Import namespaced classes with `use`, never self-import; keep global-namespace classes
  (`\Throwable`, `\DateTimeImmutable`) fully qualified inline.
- **Every handler returns a response; nothing writes to the output buffer.** This is what
  makes the package testable without a web server, and what lets a consumer emit through its
  own output channel. `mcp/sdk` does the same, which is why it composes at all.
- Failures `throw` with a stable `EXCEPTION_*` code; the endpoint maps codes to OAuth error
  responses. Never leak an internal message to a client verbatim.
- Every class gets a class-level docblock saying *why* it exists — and for anything that
  tightens a dependency (§4.1, §4.2), the docblock names the dependency behaviour it is
  compensating for, so a future reader does not "simplify" it away.
- 4 spaces, LF, final newline, no tabs; aligned `=>`/`=` runs are house style (all or nothing
  per block); separators are `// --- Name ---`; lines under ~120 characters.
- Public API changes go in `CHANGELOG.md` in the same commit.

---

## 10. Open questions

1. ~~**Key rotation policy** — key lifetime, overlapping keys in JWKS, manual or age-triggered.~~
   **Answered in P4:** manual rotation, RFC 7638 thumbprint as `kid`, and the retired public key
   published until the last token it signed has expired. See
   `docs/decisions/0004-key-rotation.md`.
2. **FileDB's O(n) lookup** (§4.5) — accept with a documented ceiling, or a purpose-built
   token store from the start? Leaning: accept, measure, revisit.
3. **Who answers DCR** (§4.4) — us or `mcp/sdk`. Exactly one.
4. **`voltcms/useraccess` constraint** — `^2.0` and test against it, rather than inheriting
   the consumer's `2.0.2` pin.
5. **Legacy-era session store** — `mcp/sdk` treats the 2025 lifecycle as stateful and needs a
   `FileSessionStore`. `SessionStoreFactory` wraps it, but where the directory lives and who
   sweeps it is a consumer-facing decision.
6. **Does this package own the `.well-known` routing** or only render the documents? Leaning:
   render only, and ship the server snippets — routing is deployment, and every host differs.

---

## 11. Developing alongside a consumer

```json
{
    "repositories": [
        { "type": "path", "url": "../voltcms-mcp", "options": { "symlink": true } }
    ],
    "require": { "voltcms/mcp": "@dev" }
}
```

`mcp/sdk` is pinned exactly (`0.8.*`): it is pre-1.0 and churns — about ten breaking changes
in 0.6.0, six in 0.8.0 — and that churn is it tracking the specification. Read its changelog
before each bump, and keep every call to it inside `Bridge/` so a break lands in one place.

Where tests live: issuance, tightenings, metadata and keys here; the consumer's tools and
consent markup there. A bug found while integrating that belongs here gets its regression test
written here, in the pull request that fixes it.

---

## 12. Sources

- `MCP_DECISION_0001_build_vs_adopt.md` and `MCP_DECISION_0002_wrap_or_write.md` — the two
  spikes, with measured package counts, the SDK's ADR text, and the flow output.
- [modelcontextprotocol/php-sdk](https://github.com/modelcontextprotocol/php-sdk) · [mcp/sdk](https://packagist.org/packages/mcp/sdk) · [SDK docs](https://php.sdk.modelcontextprotocol.io/)
- [league/oauth2-server](https://oauth2.thephpleague.com/)
- [voltcms/useraccess](https://packagist.org/packages/voltcms/useraccess) · [voltcms/filedb](https://packagist.org/packages/voltcms/filedb)
- [RFC 9728 — Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728) · [RFC 8414 — Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414) · [RFC 8707 — Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707)
- [Key Changes — Model Context Protocol (2026-07-28)](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
