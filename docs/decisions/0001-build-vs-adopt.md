# 0001 — Adopt `mcp/sdk` for the protocol; build only the authorization server

- **Status:** Accepted
- **Date:** 2026-09-03
- **Supersedes:** `MCP_SERVER_LIBRARY.md` §1.2, which scheduled this spike
- **Drop into the new repository as** `docs/decisions/0001-build-vs-adopt.md`

## Context

`MCP_SERVER_LIBRARY.md` proposed a from-scratch, dependency-free MCP server library in
vanilla PHP, with a complete OAuth 2.1 authorization server, estimated at 18–22 focused
days. Its phase 0 was a spike against the official SDK to check that the library was worth
building at all. This is the result of running that spike.

**Method.** `mcp/sdk` v0.8.1 was installed into a scratch project on PHP 8.4.19, a minimal
tool server was written against it in the shape this project's entry points actually take
(a plain PHP file, no framework, no container, superglobals in), and driven with raw
JSON-RPC over `php -S`. `league/oauth2-server` 9.4.1 was installed separately to size the
alternative the SDK's own documentation points at. Everything below is observed, not
recalled.

## The four questions, answered

### Q1 — What does it actually cost to install?

| | packages | vendor |
|---|---|---|
| `mcp/sdk` alone | **23** | 34 MB |
| plus `nyholm/psr7` + `nyholm/psr7-server` (needed for the HTTP transport) | **25** | 35 MB |
| this editor's entire root dependency list today | 7 | — |

The headline number is bad and the real number is not. Those 25 packages land in
`packages/mdeditor-mcp/vendor/`, which the entry preamble soft-includes exactly as it
already does for `packages/mdeditor-ai/vendor/autoload.php`. The editor's own root
dependency list stays at seven, `composer.lock` at the root is untouched, and deleting
`packages/mdeditor-mcp/` removes all 25 along with the feature. The "no framework"
constraint is about the editor's architecture, and an optional, deletable add-on carrying
its own vendor directory does not violate it.

### Q2 — Can it be driven from superglobals, without adopting PSR-15?

**Yes, and better than expected.** The working spike is 25 lines:

```php
$psr17   = new Psr17Factory();
$server  = Server::builder()->setServerInfo('spike-editor', '0.0.1')
    ->addTool(fn (string $path): string => 'You asked for ' . $path,
              name: 'read_post', description: 'Read one blog post by content path.')
    ->build();

$request  = (new ServerRequestCreator($psr17, $psr17, $psr17, $psr17))->fromGlobals();
$response = $server->run(new StreamableHttpTransport($request, $psr17, $psr17));

emit($response);   // ten hand-written lines: status, headers, body
```

Three findings that matter:

- **`run()` returns a PSR-7 response; it does not emit.** The SDK's own examples emit with
  `laminas/laminas-httphandlerrunner`, but that is a *dev* dependency of the SDK, not a
  runtime one — a ten-line emitter replaces it. This resolves the concern raised in
  `TODO_MCP.md` §4: the editor keeps its single output chokepoint, because
  `frontend/mcp.php` can take the returned response and emit its body through
  `Response::json()`. No fourth output channel.
- No container, no framework, no PSR-15 middleware adoption is required. Middleware exists
  and is composable, but `null` installs a sensible default stack and `[]` disables it.
- `ServerRequestCreator::fromGlobals()` is the whole bridge from this project's world to
  the SDK's.

### Q3 — Does it ship an authorization server?

**No, permanently, by written policy.** The SDK carries an accepted architecture decision
record — `adr/0001-oauth-authorization-server-out-of-scope.md`, dated 2026-06-15 — that
says so in as many words:

> **The MCP server is an OAuth 2.1 Resource Server that MAY delegate to an upstream
> authorization server. It will NOT issue tokens or act as an Identity Provider.**
>
> […] no token issuance, no token signing or key management, no login UI, no consent UI,
> no authorization-code or refresh-token storage […] Pull requests that add
> authorization-server / IdP behavior are declined by reference to this ADR.

It records that a ~3,400-line PR adding exactly that was declined, and gives the reasoning:
issuing tokens means owning key rotation, code and refresh-token persistence, rotation and
replay detection, and consent — "precisely the surface an MCP SDK should not own."

What it *does* ship on the auth side is substantial and directly useful:

| Shipped | Class |
|---|---|
| Bearer validation, 401 challenge, 403 on insufficient scope | `AuthorizationMiddleware` |
| RFC 9728 protected resource metadata | `ProtectedResourceMetadataHandler` (a mountable PSR-15 handler) |
| JWT validation, JWKS, OIDC discovery | `JwtTokenValidator`, `JwksProvider`, `OidcDiscovery` |
| RFC 7591 Dynamic Client Registration | `ClientRegistrationMiddleware` |
| Delegating `/authorize` and `/token` to an upstream IdP | `OAuthProxyMiddleware` |
| Pluggable token validation | `AuthorizationTokenValidatorInterface` — one method |

And the ADR names the supported architectures explicitly: an external IdP (Keycloak, Auth0,
Entra, Okta) **or `league/oauth2-server` running in your own application**.

This is the finding the whole spike turned on, and it cuts both ways. The SDK will never do
the hard part — but the hard part was never going to be avoided by adopting *anything*, so
it was never a reason to build the protocol layer too.

### Q4 — How stable is the pre-1.0 API?

Churny, and for a good reason. Counting `[BC Break]` entries in `CHANGELOG.md`: **0.6.0 has
about ten, 0.7.0 one, 0.8.0 about six.** Constructor signatures gained parameters in the
middle, classes were renamed with no alias, registry methods lost flags.

But 0.8.0 is what that churn bought: the entire 2026-07-28 surface — SEP-2575 lifecycle,
SEP-2322 multi-round `input_required` with signed `requestState`, SEP-2243 standard headers,
SEP-2549 cache policy, SEP-2164 error-code changes, SEP-414 trace context, plus dual-era
serving from one endpoint and deprecation of roots/sampling/logging. That is months of
specification tracking. Writing it myself would have produced the same churn on the same
schedule, with fewer tests and no second reader.

**Mitigation:** pin exactly (`"mcp/sdk": "0.8.*"`), read the changelog before each bump, and
keep the SDK behind the adapter classes in `packages/mdeditor-mcp/src/` so a breaking change
lands in one place.

## What running it actually proved

Both eras answered from one URL, with no session for the modern one:

```
initialize (2025-11-25)  → {"protocolVersion":"2025-11-25","capabilities":{...},"serverInfo":{...}}
tools/list (2026-07-28)  → {"tools":[...],"resultType":"complete","ttlMs":0,"cacheScope":"private",
                            "_meta":{"io.modelcontextprotocol/serverInfo":{...}}}
tools/call (2026-07-28)  → {"content":[{"type":"text","text":"You asked for blogs/travel/day-one"}],
                            "isError":false,"resultType":"complete", ...}
GET                      → 405
malformed JSON           → -32700
```

Three details worth keeping:

1. **It enforces SEP-2243 header validation.** A modern-era request without `Mcp-Method`
   is refused with `-32020`, and a header contradicting the body is refused too.
   `MCP_SERVER_LIBRARY.md` §6.2 planned to "accept and ignore" those headers — that reading
   was **wrong**, and the spike caught it. This is the kind of detail that makes buying the
   protocol layer worth it.
2. **It validates the modern `_meta` envelope**, rejecting a `server/discover` that omits
   `io.modelcontextprotocol/clientCapabilities`.
3. **The legacy era is stateful in this SDK.** Non-`initialize` requests without a session
   id are refused: `"A valid session id is REQUIRED for non-initialize requests."` The spec
   permits a server to omit `Mcp-Session-Id` and stay stateless, which is what the
   from-scratch plan assumed; the SDK takes the stateful reading and ships `FileSessionStore`
   with GC probability knobs for it. `StatelessHttpTransport` is modern-era only — its own
   docblock: *"Not a mode of StreamableHttpTransport, whose job is largely session
   management; without a session what is left is a POST in, one message out."*

   **Consequence for the editor:** 2026-era clients need no state, but Claude's connector
   speaks 2025-11-25 today, so a file-backed session store under `_poster/mcp/sessions/`
   is required in practice. A directory with garbage collection, not a daemon — acceptable
   on shared hosting, but it must be planned for, and it is new information.

## The alternative the ADR points at

`league/oauth2-server` 9.4.1, sized in the same way:

- **13 packages**, PHP `~8.2 … ~8.5`, needs `ext-openssl`.
- Ships `AuthCodeGrant` and `RefreshTokenGrant`, and **PKCE with an `S256Verifier`**.
- Issues **JWT** access tokens (`lcobucci/jwt`) — which pairs directly with the SDK's
  `JwtTokenValidator` and `JwksProvider`. The two halves are designed to meet.
- You implement **seven repository interfaces** (client, access token, auth code, refresh
  token, scope, user, device code). With no database, those become filesystem stores.
- Ships **no RFC 8414 authorization-server metadata** (confirmed by inspection), no consent
  UI, and nothing for Client ID Metadata Documents — which the 2026-07-28 revision prefers
  over the DCR both it and the SDK implement.

## Decision

**Adopt `mcp/sdk` for the protocol layer. Do not build one.**

Building a competing protocol library would mean re-deriving SEP-2243, SEP-2549, SEP-2575,
SEP-2322, dual-era dispatch and the `_meta` envelope — and the spike has already shown one
place where my reading of the spec was wrong before a line was written. The dependency
objection, the one real argument for building, is answered by putting the SDK in the
add-on's own vendor directory where it is deletable along with the feature.

**The new repository still has a reason to exist, but a much smaller one:** the
authorization server, which `mcp/sdk` has permanently ruled out, which every self-hosted
single-tenant PHP application needs, and which nothing in the ecosystem provides in a
filesystem-only, no-IdP shape.

Its scope collapses from *"an MCP server library"* to *"an OAuth 2.1 authorization server
for single-tenant PHP applications, wired to plug into
`AuthorizationTokenValidatorInterface`"* — roughly **5–9 days instead of 18–22**, and a
sharper, more defensible package than the original.

## Consequences

- `MCP_SERVER_LIBRARY.md` is rewritten to the reduced scope. Its §4–§7 (protocol core,
  tools, HTTP transport) are dead; §8 (authorization) becomes the whole library.
- `TODO_MCP.md`'s adapter package requires `mcp/sdk` and gains a session store for
  legacy-era clients.
- The editor's §4 output-channel concern is resolved: `run()` returns a response.
- The tools, content services, path policy, front-matter handling and all eleven findings
  about the editor's own code are **unaffected** — they were never about whose protocol
  code runs underneath.

## Next decision

**0002 — build the authorization server, or wrap `league/oauth2-server`?** The spike sized
both sides but did not answer it. Wrapping means 13 more packages and seven filesystem
repository implementations, against a mature, widely-deployed token issuer with PKCE
already correct. Building means no dependency and a store shaped the way we want, against
owning key rotation and replay detection — the exact liability `mcp/sdk`'s ADR declined.
Either way the new repository still owns RFC 8414 metadata, the consent UI, CIMD, and the
filesystem stores. **Recommendation: wrap.** Token issuance is a solved problem and a bad
place to be original.
