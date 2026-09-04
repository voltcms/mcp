# Security

`voltcms/mcp` issues credentials. This document states what it guarantees, what it does *not*,
and how to report a problem.

> **Pre-release.** The implementation is complete and tested, but no version has been tagged and
> no independent review has happened. Until `0.1.0`, treat this package as unreviewed and do not
> point it at production credentials.

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

- **PKCE with `S256`, and nothing else.** A `code_challenge_method` of `plain` — or an absent
  one, which RFC 7636 defaults to `plain` — is refused before the request reaches
  `league/oauth2-server`, which would otherwise accept both. PKCE is required of every client,
  confidential ones included.
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
- **Revocation takes effect immediately.** Validation reads the token store on every request, so
  a revoked access token stops working at once rather than running out its hour. Revoking either
  end of a grant revokes both — the access token and the refresh token issued with it. The cost
  of that lookup was measured before it was accepted; see
  [`docs/decisions/0005-validation-reads-the-store.md`](docs/decisions/0005-validation-reads-the-store.md).
- **A token can never carry a scope its granting user's roles do not support.**
- **A missing store record reads as revoked**, never as valid.
- **Identifiers are matched exactly.** Client ids and token identifiers are compared with
  `hash_equals()` against the stored value, never through the flat-file store's own search,
  which matches case-insensitively and treats `*` as a wildcard. A `client_id` of `claude*`
  resolves no client.
- **Throttling** on authorize, token and revoke, keyed by identifier + IP, in a separate bucket
  per endpoint so probing one cannot lock a user out of another.
- **A `resource` parameter naming another server is refused** with `invalid_target`, rather than
  answered with a token for this one (RFC 8707).
- **A consent approval is bound to the request it was shown for** — the user, the client, the
  redirect URI, the granted scopes, the code challenge and the state — so a cross-site POST
  cannot approve an authorization request.
- **Every issuance, refresh and revocation is written to the audit log.**
- **Client ID Metadata Document fetches are guarded**: HTTPS on the default port only, no
  redirects at all, no private, loopback, link-local or reserved address — checked against every
  address the host resolves to, not the hostname — a 64 KB cap, a five-second timeout, and both
  answers and refusals cached so a `client_id` naming somebody else's URL cannot make this server
  an amplifier. Where `ext-curl` is available the connection is pinned to the approved address, so
  DNS is resolved once; where it is not, that race remains and
  [`docs/decisions/0006-who-answers-registration.md`](docs/decisions/0006-who-answers-registration.md)
  says so.
- **A client metadata document must claim the URL it was served from.** Otherwise
  `https://attacker.example/client.json` could serve a document naming itself Claude, and a user
  would approve a consent screen naming Claude while the code went elsewhere.
- **Dynamic client registration is off unless a deployment asks for it**, because an open
  registration endpoint is an unauthenticated write endpoint on the credential store.

## What this package does not guarantee

**A token already in flight is not recalled.** Revocation stops the *next* request; a request
already being served with a token revoked a moment ago finishes. Access tokens are JWTs with a
**one-hour TTL**, and the TTL is what bounds a token that is never revoked at all.

**Anyone holding an access token can read its claims.** They are signed, not encrypted. Do not
put anything secret in a scope name, a client id or a subject identifier.

**A stolen token still works until it is revoked.** Re-checking scopes against the live account
catches deactivation and role removal; it does not catch a token lifted from a client that is
otherwise in good standing. Short TTLs and revoking the grant are the answer there.

**Validation fails closed, which means an unreadable store refuses everything.** A missing record
reads as revoked, so a token store that has been emptied, moved or made unwritable rejects every
token rather than accepting every token. That is the right direction, and it is an outage — back
the store up (see below).

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
