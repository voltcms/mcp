# Security

`voltcms/mcp` issues credentials. This document states what it guarantees, what it does *not*,
and how to report a problem.

> **Pre-release.** No version has been tagged yet. Until `0.1.0`, treat this package as
> unreviewed and do not point it at production credentials.

## Reporting a vulnerability

Please **do not open a public issue.**

- Preferred: GitHub's private vulnerability reporting on this repository
  (*Security → Report a vulnerability*).
- Alternatively, email <github@jrondorf.de> with "voltcms/mcp security" in the subject.

Expect an acknowledgement within seven days. This is a small project maintained by one person;
fixes are prioritised by exploitability, and a fix ships as a patch release with a
`CHANGELOG.md` entry.

## What this package guarantees

Each of these is backed by a test that fails if the guarantee breaks.

- **PKCE with `S256`, and nothing else.** A `code_challenge_method` of `plain` is refused
  before the request reaches `league/oauth2-server`, which would otherwise accept it. PKCE is
  required for public clients.
- **Audience binding (RFC 8707).** An issued access token's `aud` is the *resource* — the
  canonical MCP endpoint URL — not the client id, so a token minted for one server cannot be
  replayed at another.
- **The issuer URL comes from configuration, never from a request header.** `Host` is
  attacker-controlled; configuration refuses to construct without an explicit issuer rather
  than guessing one from `$_SERVER`.
- **Authorization codes are single-use** and short-lived; a replayed code is refused.
- **Refresh tokens rotate on use.**
- **`redirect_uri` is matched exactly** — a trailing slash, an added query parameter or a
  changed case is a different URI.
- **Scopes are re-checked against the live user record on every validation.** A deactivated
  account or a removed role invalidates a live token *now*, not at expiry.
- **A token can never carry a scope its granting user's roles do not support.**
- **A missing store record reads as revoked**, never as valid.
- **Identifiers are matched exactly.** Client ids and token identifiers are compared with
  `hash_equals()` against the stored value, never through the flat-file store's own search,
  which matches case-insensitively and treats `*` as a wildcard. A `client_id` of `claude*`
  resolves no client.
- **Throttling** on authorize, token and register, keyed by identifier + IP.
- **Every issuance, refresh and revocation is written to the audit log.**
- **Client ID Metadata Document fetches are guarded**: HTTPS only, no cross-host redirects, no
  private or link-local addresses, a size cap, a cached TTL, and a timeout short enough for
  shared hosting.

## What this package does not guarantee

**Access-token revocation is not instant.** Access tokens are JWTs with a **one-hour TTL**.
They are self-contained and readable by anyone holding one, and validating them does not hit
the store on every request — so an access token revoked at minute five may keep working until
minute sixty.

What *is* immediate is revoking the **grant**: the refresh path dies at once, so the client
cannot obtain another token. That is the control that matters, and it is the trade the JWT
design makes deliberately. If you need instant access-token revocation, use an external
identity provider instead (see the README's "When to use an external IdP instead").

Two further limits, stated plainly:

- Anyone holding an access token can read its claims. Do not put anything secret in a scope
  name or a subject identifier.
- Scope re-checking on validation catches deactivation and role removal. It does not catch a
  token stolen from a client that is still perfectly valid — short TTLs and revoking the grant
  are the answer there.

## Deployment requirements

These are not optional, and the package cannot enforce them from inside:

1. **Serve over HTTPS.** The MCP authorization spec requires it. `localhost` is exempt for
   development only.
2. **Put the token store and the signing key outside the web root.** Deny-all files inside the
   web root are defence in depth for hosts where that is impossible — they are not a
   substitute.
3. **The private signing key is `0600`** and is never committed. `.gitignore` excludes the key
   directory; check your deployment tooling does the same.
4. **Keep the encryption key out of the codebase** — environment variable or a file outside
   the web root, not a constant in a PHP file.
5. **Back up the store.** Losing it invalidates every live grant; leaking it is a credential
   breach.

## Dependencies

Security fixes in `mcp/sdk`, `league/oauth2-server` and `voltcms/useraccess` are tracked and
released as patch versions here. `mcp/sdk` is pinned to `0.8.*` because it is pre-1.0 and
churns; its changelog is read before every bump.

Two behaviours of `league/oauth2-server` are compensated for rather than configured, because
its public API does not allow configuring them — the `plain` PKCE verifier and the client-id
audience claim. Both have tests designed to **fail loudly** if a `league` upgrade changes the
behaviour underneath us. If one of those tests fails after an upgrade, treat it as a security
regression and stop.
