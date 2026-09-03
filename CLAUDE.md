# CLAUDE.md

Guidance for Claude Code when working in `voltcms/mcp`.

## What this repository is

`voltcms/mcp` makes a flat-file PHP application speak MCP to a remote client — a Claude
session, a ChatGPT session, Claude Code — with real OAuth, **no identity provider, no
database and no daemon**.

It composes three packages and adds the piece nobody else has:

| Layer | Provided by |
|---|---|
| MCP protocol, both eras, HTTP transport, tools | `mcp/sdk` (pinned `0.8.*`) |
| Token issuance: codes, PKCE, refresh rotation | `league/oauth2-server` `^9.4` |
| Users, groups, sessions, flat-file store, locking, throttle, audit | `voltcms/useraccess` `^2.0` |
| **Everything between them** | **this package** |

That last row — FileDB-backed OAuth repositories, the S256-only and RFC 8707 tightenings over
league, RFC 8414 metadata, the consent seam, Client ID Metadata Documents, signing-key
management, and the bridge that hands `mcp/sdk` a validator for the tokens league minted — is
the entire reason this repository exists. **Work that belongs in one of the three dependencies
does not belong here.**

### Read before writing code

- `PLAN.md` — the full plan: architecture (§3), what we add over our dependencies (§4),
  security posture (§5), testing (§6), delivery phases (§8), open questions (§10).
- `docs/decisions/0001-build-vs-adopt.md` — why we adopt `mcp/sdk` rather than write a
  protocol layer.
- `docs/decisions/0002-wrap-or-write.md` — why we wrap `league/oauth2-server` rather than
  write an issuer, and what `voltcms/useraccess` already gives us.

Both decision records are the output of spikes that were actually run. Their findings are
observations, not guesses — when code here looks redundant, check them before removing it.

## Commands

```bash
composer install
vendor/bin/phpunit                          # whole suite
vendor/bin/phpunit --filter S256            # one case
composer validate --strict
```

CI runs the suite on PHP 8.2, 8.3 and 8.4. All three must stay green: this package issues
credentials.

## Layout

```
src/
    McpServer.php  OAuthServer.php  Configuration.php   # façades + explicit config
    OAuth/         Repositories/ Entities/ Endpoints/ Keys/ Clients/
    Identity/      UserAccessIdentityProvider, Identity, ScopePolicy
    Bridge/        every call into mcp/sdk lives here
    Contracts/     the seams a consumer varies
    Http/          Request / Response
tests/                                                  # mirrors src/
docs/decisions/                                         # ADRs
examples/blog/                                          # the full flow, end to end
```

There is no `Storage/` and no `Support/`: `voltcms/useraccess` is both — `FileDB` is the
store, `Lock` the mutex, `AuditLog` the audit sink, `LoginThrottle` the throttle. Reach for
those before writing a new one.

A consumer implements exactly two interfaces, and neither is about security:
`ConsentViewInterface` (their markup) and `LoginRedirectorInterface` (their login page).
Identity is concrete — `UserAccessIdentityProvider` — not an interface a consumer must fill.

## Non-negotiables

These exist because a spike found the dependency doing something we cannot ship. Each one
carries a class-level docblock naming the behaviour it compensates for. **Do not "simplify"
any of them away, and do not weaken their tests.**

1. **S256 only.** `league`'s `AuthCodeGrant` registers a `PlainVerifier` next to the
   `S256Verifier`; `$codeChallengeVerifiers` is `private` and the only public PKCE method
   *weakens* the requirement. A `plain` challenge was **accepted** in the spike.
   `AuthorizeEndpoint` rejects any `code_challenge_method` other than `S256` before
   delegating. (PLAN.md §4.1)
2. **`aud` is the resource, not the client.** league's JWT carries `aud = <client id>`;
   RFC 8707 and the MCP spec want the resource — the endpoint's canonical URL — so a token
   minted for one server cannot be replayed at another. `AccessTokenTrait::convertToJWT()` is
   `private`, so `ResourceBoundAccessToken` implements `AccessTokenEntityInterface` directly.
   (PLAN.md §4.2)
3. **The issuer URL is configuration, never a header.** `$_SERVER['HTTP_HOST']` is
   attacker-controlled; a forged `Host` would publish an attacker's origin as the
   authorization server. `Configuration` refuses to construct without an explicit issuer.
   (PLAN.md §4.3)
4. **Every handler returns a response. Nothing writes to the output buffer** — no `echo`, no
   `header()`, no `exit`. This is what makes the package testable without a web server and
   what lets a consumer emit through its own output channel. `mcp/sdk` does the same, which
   is why it composes at all.
5. **Every call into `mcp/sdk` lives in `Bridge/`.** The SDK is pre-1.0 and churns — about ten
   breaking changes in 0.6.0, six in 0.8.0 — so a break must land in one directory. Read its
   changelog before any bump.
6. **No network in tests, ever.** The CIMD fetcher is injected and stubbed.

Items 1 and 2 are *upgrade tripwires*: their tests must fail loudly if a dependency upgrade
changes behaviour underneath us.

## Coding standards

- PSR-4, one class per file, `declare(strict_types=1);` in every file.
- Methods and properties `camelCase`; class constants `SCREAMING_SNAKE` with explicit
  visibility, declared at the top of the class. Target is PHP 8.2 — **no typed class
  constants** (8.3+), no property hooks, no asymmetric visibility (8.4+).
- No global constants, no `global` / `$GLOBALS` — state arrives through the constructor.
- Every parameter, return and property typed.
- Allman braces for class and function declarations, K&R for control flow:

```php
final class ScopePolicy
{
    public function grantableFor(Identity $identity): array
    {
        if ($identity->roles === []) {
            return [];
        }

        return $this->map($identity);
    }
}
```

- Import namespaced classes with `use`, never self-import; keep global-namespace classes
  (`\Throwable`, `\DateTimeImmutable`) fully qualified inline.
- Failures `throw` with a stable `EXCEPTION_*` code; the endpoint maps codes to OAuth error
  responses. **Never leak an internal message to a client verbatim.**
- Every class gets a class-level docblock saying *why* it exists — and for anything that
  tightens a dependency, the docblock names the dependency behaviour it compensates for, so a
  future reader does not simplify it away.
- 4 spaces, LF, final newline, no tabs; aligned `=>` / `=` runs are house style (all or
  nothing per block); separators are `// --- Name ---`; lines under ~120 characters.

## Testing

PHPUnit 11, `tests/` mirroring `src/`. `assertSame` over `assertEquals`. **One explicit test
per case, no data providers** — a named failing test says what broke. Temp directories go
through the shared helper, never `sys_get_temp_dir()` inline.

Test the guarantees we *promise*, including the ones league implements, because we are the
ones promising them: PKCE required for public clients; codes single-use and TTL-bound;
refresh rotation; exact `redirect_uri` matching including near misses (trailing slash, added
query, case). A missing store record must read as **revoked**, never as valid. A user
deactivated or demoted *after* issue must fail validation.

## Workflow

- Public API changes go in `CHANGELOG.md` **in the same commit**.
- A decision that changes the shape of the package gets a numbered record in
  `docs/decisions/`, in the style of the two already there: context, what was measured,
  decision, consequences.
- PLAN.md §10 lists six open questions. Answering one means updating PLAN.md — or writing a
  decision record — rather than deciding it silently in code.
- Security-relevant behaviour that `SECURITY.md` promises must have a test that fails when the
  promise breaks.
