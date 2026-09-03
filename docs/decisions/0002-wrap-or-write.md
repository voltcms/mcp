# 0002 — Wrap `league/oauth2-server`; build the MCP package on `voltcms/useraccess`

- **Status:** Accepted
- **Date:** 2026-09-03
- **Follows:** `MCP_DECISION_0001_build_vs_adopt.md`, which adopted `mcp/sdk` for the
  protocol and left the authorization server as the new repository's only reason to exist
- **Drop into the new repository as** `docs/decisions/0002-wrap-or-write.md`

## Context

Decision 0001 established that `mcp/sdk` will never issue tokens — its own ADR rules an
authorization server permanently out of scope — and cut the planned library down to that one
job. It left the next question open: **write the issuer, or wrap `league/oauth2-server`**,
which the SDK's ADR itself points at.

Two things changed alongside this spike: the new repository is **`voltcms/mcp`** with
namespace **`VoltCMS\MCP`**, and a dependency on **`voltcms/useraccess`** is permitted. The
second is not a detail — it decides how much of the library is left to write at all.

**Method.** `league/oauth2-server` 9.4.1 was installed on PHP 8.4 and given a real,
flat-file integration: five repositories and six entities backed by `voltcms/filedb`, then a
complete authorization-code flow driven end to end — authorize, consent, code, PKCE
exchange, refresh, and four abuse cases. `voltcms/useraccess` 2.0.2 was installed and read.
Everything below is observed.

## What `voltcms/useraccess` already provides

This is the finding that reshapes the library. For **three packages**
(`voltcms/useraccess`, `voltcms/filedb`, `bramus/router` — the last already a root
dependency of the consuming editor), it ships:

| Component | What it is | What it replaces in the plan |
|---|---|---|
| `VoltCMS\FileDB\FileDB` | JSON flat-file CRUD: `create`, `read` (by id or by field search), `readAll`, `update`, `delete`, `setReadonly` | the whole `Storage/` layer |
| `Lock` | **reentrant** advisory write mutex over `flock(LOCK_EX)`, with a depth counter so nested acquisitions do not self-deadlock | the hand-rolled `flock` around refresh rotation |
| `AuditLog` | `record(array $entry)` to an append-only file | `AuditSinkInterface` + `FileAuditLog` |
| `LoginThrottle` | `key()` / `isLocked()` / `registerFailure()` / `reset()`, keyed by identifier + IP, windowed | `ThrottleInterface` + `FilesystemThrottle` |
| `UserProvider`, `GroupProvider`, `SessionAuth`, `User`, `Group` | the identity model, sessions, group membership | the consumer's identity adapter — now shippable *concretely* |
| `BearerAuth` | static-secret bearer validation for SCIM: sha256 digests, constant-time compare, `REDIRECT_HTTP_AUTHORIZATION` fallback | not reusable directly (no per-user lookup), but the **pattern** to copy for token storage |

Two consequences:

1. `VoltCMS\MCP` can ship a **concrete** `UserAccessIdentityProvider` rather than only an
   interface. The consuming application implements nothing to get identity — it passes the
   same users/ and groups/ directories it already uses.
2. The library's `Storage/` and `Support/` layers largely disappear. They were about a third
   of the planned surface.

### One constraint that shapes the design

`FileDB::create()` **always generates its own UUID**; the caller cannot choose the document
id. So an OAuth identifier cannot be the filename, and lookups go through
`read(null, ['oauth_id' => …])`, which FileDB implements as `readAll()` plus a scan — **O(n)
per token validation**, with the record's own id under `_id`, not `id`.

At personal-blog scale (a handful of clients, a few live tokens) this is irrelevant. As a
general-purpose library it is a documented ceiling, and the mitigation if it ever bites is a
purpose-built token store rather than FileDB for that one collection. Recorded rather than
solved.

## What the `league/oauth2-server` integration actually costs

**180 lines**, in two files:

| File | Lines | Contents |
|---|---|---|
| `entities.php` | 51 | six entities — `Client`, `Scope`, `AccessToken`, `AuthCode`, `RefreshToken`, `User`. league's traits do nearly all the work; most classes are a `use` statement and a constructor. |
| `repositories.php` | 129 | the five repositories the auth-code and refresh grants need — 14 methods, all trivial CRUD over `FileDB` — plus a shared base class for find/put/revoke. |

`DeviceCodeRepositoryInterface` is not needed: it belongs to `DeviceCodeGrant`, which we do
not enable.

### The flow, run end to end

```
1. authorize    -> 302 redirect, state=xyz, code=def50200…
2. token        -> 200 Bearer, expires_in=3600, access_token is a JWT of 694 chars,
                   refresh_token present=yes
3. refresh      -> 200 new access token issued, rotated refresh=yes
4. code replay  -> refused: "Authorization code has been revoked"
5. bad verifier -> refused: invalid grant
```

And the authorize-side abuse cases:

```
A. PKCE omitted     -> refused: "Code challenge must be provided for public clients"
B. plain challenge  -> ACCEPTED
C. foreign redirect -> refused: client authentication failed
```

Refresh rotation, single-use codes, PKCE requirement for public clients and exact
`redirect_uri` matching are all correct out of the box. That is the entire dangerous core of
an authorization server, working, in an afternoon.

### Two places the wrapper must reach past league's API

Wrapping is not "just use it". The spike found exactly two gaps, and both are the wrapper's
job to close:

**1. `plain` PKCE is accepted, and cannot be turned off through the public API.**
Case B above. `AuthCodeGrant::__construct()` registers both an `S256Verifier` and a
`PlainVerifier`, `private array $codeChallengeVerifiers` is not reachable from a subclass,
and the only PKCE-related public method is `disableRequireCodeChallengeForPublicClients()`
— which *weakens* the requirement. OAuth 2.1 and the MCP authorization spec both want S256
only.

**Fix:** reject any `code_challenge_method` other than `S256` in our own authorize endpoint,
before delegating to league. Roughly five lines, and it must be covered by a test that fails
loudly if a league upgrade ever changes the constructor.

**2. The JWT's `aud` is the client id, not the resource.**
The issued token carries `aud, jti, iat, nbf, exp, sub, scopes` — signed RS256, with
`aud="claude-desktop"` and `scopes=["mcp:read","mcp:write"]`. RFC 8707 audience binding, which
the MCP spec requires, wants the audience to be the **resource** — the MCP endpoint's
canonical URL — so that a token minted for one resource cannot be replayed at another.
`AccessTokenTrait::convertToJWT()` is `private`, so the claims cannot be extended by
subclassing.

**Fix:** implement `AccessTokenEntityInterface` directly instead of using
`AccessTokenTrait`, building the JWT with `lcobucci/jwt` (already a league dependency) and
adding the resource. About forty lines, and the place where the library earns its keep.

## Footprint

| Stack | packages |
|---|---|
| `league/oauth2-server` alone | 13 |
| `mcp/sdk` alone | 23 |
| `voltcms/useraccess` alone | 3 |
| **the union the add-on actually installs** (plus `nyholm/psr7` + `psr7-server`) | **35** |

Vendor size for that union: **23 MB**. (A first measurement said 81 MB; that was an artifact
of this environment installing from *source* — 35 `.git` directories of full history. Dist
installs are the real case.)

Thirty-five packages is a lot next to the editor's seven, and it stays acceptable for exactly
the reason decision 0001 gave: they live in `packages/mdeditor-mcp/vendor/`, soft-included the
way the AI add-on's already is, and deleting the add-on removes all of them. The nine `psr/*`
interface packages are shared between `mcp/sdk` and `league/oauth2-server` rather than
duplicated — the two halves were designed to meet.

## Decision

**Wrap `league/oauth2-server`. Build `voltcms/mcp` on it and on `voltcms/useraccess`.**

The reasoning is the same one `mcp/sdk`'s ADR gave for declining to be an authorization
server, and it applies with more force to a one-person project: issuing tokens means owning
PKCE verification, single-use code semantics, refresh rotation with replay detection, and
signing-key handling. The spike had all of that working correctly in 180 lines of glue. A
from-scratch implementation would spend a week reaching the same place with one reader
instead of thousands.

What `voltcms/mcp` is, then:

- **`mcp/sdk`** speaks the protocol.
- **`league/oauth2-server`** issues the tokens.
- **`voltcms/useraccess`** stores users, groups, files, locks, throttles and the audit log.
- **`voltcms/mcp`** is the part nobody else has: the flat-file repositories, the S256-only
  and RFC 8707 tightenings, the RFC 8414 metadata document, the consent seam, Client ID
  Metadata Documents, key management, and the bridge that hands `mcp/sdk` a validator for the
  tokens league minted.

## Consequences

- The library's estimate drops again — roughly **4–7 days**, from the 5–9 that assumed a
  hand-written issuer and hand-written stores.
- `Storage/` and most of `Support/` leave the plan; `Contracts/` shrinks to the seams a
  consumer genuinely varies (consent rendering, login redirection, scope policy).
- The consuming editor's identity adapter mostly disappears: `VoltCMS\MCP` ships a concrete
  `UserAccessIdentityProvider`, so the editor passes directories rather than implementing an
  interface.
- **Access tokens are JWTs, not opaque strings.** That reverses the from-scratch plan's
  "opaque, stored as a sha256" design for access tokens. Refresh tokens and codes stay
  stored (they must, for rotation and replay detection), but an access token is now
  self-contained and readable by anyone holding it, and revoking one before expiry means a
  store lookup on every request anyway if we want it to be immediate. **Keep the TTL short
  (one hour) and accept that revocation of an access token is not instant; revoking the
  grant kills the refresh path immediately.** Say so plainly in `SECURITY.md`.
- **Key management is now real work** that the opaque-token design avoided: generating an
  RS256 keypair, storing the private key outside the web root with `0600`, rotating it, and
  publishing a JWKS endpoint. `mcp/sdk` ships `JwksProvider` and `JwtTokenValidator` to
  consume it, so the two ends meet — but the generation, storage and rotation are ours, and
  they belong in the library rather than in every consumer.
- Two upgrade tripwires need tests that fail loudly rather than silently: the S256-only guard
  (a league change to the verifier registration would otherwise re-enable `plain`) and the
  custom access-token entity (a change to `AccessTokenTrait` would otherwise drop the
  resource claim).

## Open questions carried forward

1. **Key rotation policy** — how long a signing key lives, how overlapping keys are published
   in JWKS, and whether rotation is manual or age-triggered.
2. **FileDB's O(n) lookup** (above) — accept with a documented ceiling, or a purpose-built
   token store from the start? Leaning: accept, measure, revisit if a consumer needs scale.
3. **Who answers Dynamic Client Registration** — `mcp/sdk` ships DCR middleware and so might
   we. Exactly one must, and 2026-07-28 prefers CIMD over DCR anyway.
4. **`voltcms/useraccess` version constraint** — the editor pins `2.0.2` exactly. The library
   should express a range it actually tests against, not inherit that pin by accident.
