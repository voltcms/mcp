# Release checklist — the live pass before `0.1.0`

The test suite proves each piece of this package in isolation, and `McpServerTest` proves the two
halves meet. What none of it proves is that a **real client** — one nobody here wrote, following the
MCP specification rather than our reading of it — can discover this server, authorize against it and
call a tool.

That is what this document is for. It is a runbook: work top to bottom, and each step says what to
run, what a good result looks like, and what to do when it is not.

> **Every command below has been run.** The outputs shown are real, captured against
> `examples/blog` on PHP 8.4. Where a step is expected to *fail* as things stand, it says so and
> says why.

**Time:** about two hours for steps 0–5 if nothing surprises you. Step 6 needs an hour of waiting.

**Contents**

| | |
|---|---|
| [Step 0](#step-0--fix-the-one-thing-we-already-know-is-wrong) | The RFC 9728 path, before you deploy anything |
| [Step 1](#step-1--stand-up-a-reachable-host) | A host, a certificate, a store, a user |
| [Step 2](#step-2--walk-the-discovery-chain-by-hand) | Five `curl`s, before any client |
| [Step 3](#step-3--decide-how-the-client-gets-a-client_id) | CIMD, pre-registration, or DCR |
| [Step 4](#step-4--mcp-inspector) | The forgiving client, first |
| [Step 5](#step-5--a-real-claude-client) | Claude Code, then claude.ai |
| [Step 6](#step-6--exercise-what-only-a-live-pass-can-reach) | Refresh, revocation, rotation, demotion |
| [Step 7](#step-7--record-the-result-and-tag) | Write it down, tag `0.1.0` |
| [Appendix A](#appendix-a--failure-index) | Symptom → cause → fix |
| [Appendix B](#appendix-b--running-the-example-locally) | The local loop, in full |

---

## Step 0 — fix the one thing we already know is wrong

**Do this before deploying.** It needs no host, and it is the most likely first failure.

### What is wrong

RFC 9728 §3 says a protected resource publishes its metadata at a URL formed by inserting
`/.well-known/oauth-protected-resource` **between the host and the resource's path**:

| Resource identifier | Metadata URL the client asks for |
|---|---|
| `https://example.com/mcp` | `https://example.com/.well-known/oauth-protected-resource/mcp` |
| `https://example.com` | `https://example.com/.well-known/oauth-protected-resource` |

`Bridge\ProtectedResourceMetadata::forConfiguration()` does not pass `metadataPaths`, so the SDK
falls back to its default of the bare path only. Reproduced against a running server:

```console
$ curl -sS -o /dev/null -w '%{http_code}\n' http://localhost:8080/.well-known/oauth-protected-resource/mcp
404
$ curl -sS http://localhost:8080/.well-known/oauth-protected-resource
{"authorization_servers":["http://localhost:8080"],"scopes_supported":["mcp:read","mcp:write"],…}
```

A client that follows the RFC asks for the first URL, gets a 404, and stops. It never reaches the
authorization server at all.

RFC 8414 §3.1 has the same rule for an **issuer with a path** — issuer `https://example.com/blog`
means AS metadata at `/.well-known/oauth-authorization-server/blog`. `MetadataEndpoint::WELL_KNOWN_PATH`
is a bare constant, so it is correct only for a path-less issuer. If you deploy at the root of a
domain this second one costs you nothing; if you deploy under a path it will bite.

### What to change

1. **`src/Bridge/ProtectedResourceMetadata.php`** — compute the paths from the resource URL and pass
   both to the SDK, path-inserted first (it becomes `getPrimaryMetadataPath()`, which is what the
   `WWW-Authenticate` challenge advertises):

   ```php
   $path  = (string) parse_url($configuration->resource, PHP_URL_PATH);
   $paths = $path === '' || $path === '/'
       ? [SdkProtectedResourceMetadata::DEFAULT_METADATA_PATH]
       : [SdkProtectedResourceMetadata::DEFAULT_METADATA_PATH . '/' . trim($path, '/'),
          SdkProtectedResourceMetadata::DEFAULT_METADATA_PATH];
   ```

   Keeping the bare path as a fallback costs one array entry and accommodates clients that only ask
   for it.

2. **`src/McpServer.php`** — add `resourceMetadataPaths(): array` returning
   `$this->resourceMetadata->getMetadataPaths()`. Keep `resourceMetadataPath()` for the primary.

3. **`src/OAuth/Endpoints/MetadataEndpoint.php`** — add a
   `wellKnownPathFor(Configuration $configuration): string` that path-inserts the issuer's path, and
   keep `WELL_KNOWN_PATH` as the constant for the common case.

4. **`examples/blog/public/mcp.php`** — the `match` matches one path per document; it needs to match
   any of the set. Replace those two arms with a check against `in_array($path, …, true)`.

### How to know it worked

Add to `tests/Bridge/ProtectedResourceMetadataTest.php`:

- a resource with a path publishes the path-inserted URL as its **primary** path;
- a resource without one publishes only the bare path;
- the bare path is still in the list either way.

Then re-run [Appendix B](#appendix-b--running-the-example-locally) and confirm the `curl` at the top
of this step returns `200` instead of `404`.

- [ ] Path-inserted metadata paths implemented, tested, suite green

---

## Step 1 — stand up a reachable host

### 1.1 What the host must have

| Requirement | Why |
|---|---|
| PHP 8.2, 8.3 or 8.4 with `ext-json`, `ext-openssl` | What CI tests |
| `ext-curl` (optional, recommended) | Pins CIMD fetches to the approved IP, closing the DNS-rebinding race (ADR 0006) |
| **HTTPS with a real certificate** | `Configuration` refuses plain `http` for anything but loopback, and clients refuse it too |
| A writable directory **outside the web root** | Tokens and the signing key. Deny-all files are defence in depth, not a substitute (SECURITY.md) |
| Ability to rewrite `/.well-known/…` to PHP | Without it, discovery cannot start |

**It cannot be `localhost`.** claude.ai reaches your server from Anthropic's infrastructure, so it
needs a publicly resolvable HTTPS URL. Three ways, in increasing order of effort:

| Option | Command | Trade-off |
|---|---|---|
| **Tunnel** | `cloudflared tunnel --url http://localhost:8080` | Fastest. URL changes per run, so `MCP_ISSUER` and `MCP_RESOURCE` must change with it, and every registered client's `client_id` is scoped to the old URL |
| **Shared host** | Upload; point the vhost at `examples/blog/public` | Closest to the real target deployment |
| **VPS** | Caddy or nginx + php-fpm | Most control; stable URL, so you can leave it running for step 6 |

For a first pass a tunnel is fine. For step 6 you want something that survives an hour, so a VPS or
shared host is easier there.

### 1.2 Configure it

`examples/blog/bootstrap.php` reads four environment variables. Nothing is derived from the request
— that is the whole of PLAN.md §4.3, and it is why these have to be set explicitly.

```bash
export MCP_ISSUER=https://mcp.example.com          # your PUBLIC origin, no trailing slash
export MCP_RESOURCE=https://mcp.example.com/mcp    # the MCP endpoint's canonical URL
export MCP_STORAGE=/var/private/example-blog       # OUTSIDE the web root
export MCP_ENCRYPTION_KEY="$(php -r 'echo base64_encode(random_bytes(32));')"
```

> **`MCP_ENCRYPTION_KEY` is a credential.** league encrypts authorization codes and refresh tokens
> with it, and `ConsentTicketSigner` signs consent tickets with it. Losing it invalidates every live
> grant; leaking it is a breach. Put it in the process environment or a file outside the web root —
> never a constant in a PHP file, never in git.

Make sure the environment reaches PHP-FPM (`env[MCP_ISSUER] = …` in the pool config) or Apache
(`SetEnv`) — a variable exported in your shell will not be visible to the web server.

### 1.3 Route the paths

The front controller handles seven paths. Everything else must be served normally.

**Apache** — `.htaccess` at the document root:

```apache
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteRule ^(mcp|oauth/.*|\.well-known/.*)$ /mcp.php [L,QSA]
```

**nginx**:

```nginx
location ~ ^/(mcp$|oauth/|\.well-known/) { try_files $uri /mcp.php$is_args$args; }
```

> Some hosts ship a literal `.well-known/` directory that shadows the rewrite, and some serve it
> for ACME and nothing else. Confirm with step 2.1 before debugging anything else.

### 1.4 First run, and the keypair

Hit any endpoint once. `OAuthServer`'s constructor calls `KeyManager::ensureKeyPair()`, so the
keypair is generated on first use — there is no install step.

```bash
curl -sS https://mcp.example.com/oauth/jwks
ls -la $MCP_STORAGE/keys/    # -a, or you will not see the .htaccess
```

Expected: `private.key` at `-rw-------` (0600), `public.key` at `0644`, and an `.htaccess` beside
them. If the mode is anything else, stop — `KeyManager::writeFile()` sets it before writing a byte,
so a wrong mode means something else is rewriting the file.

### 1.5 Create a user and a client

```bash
php examples/blog/bin/create-user.php jannis 'a-real-passphrase' editors
```

```console
Created user jannis
  id: d6bf46cb-0172-45b5-ac13-ba183a4dff81
  added to group: editors
```

The group name matters: `bootstrap.php` maps `editors` to `mcp:read mcp:write` and gives everyone
else `mcp:read` only. Passwords must be at least 8 characters (`User::PASSWORD_MIN_LENGTH`).

Leave client registration until [step 3](#step-3--decide-how-the-client-gets-a-client_id) — you want
the client's real `redirect_uri`, not a guess.

- [ ] Reachable over HTTPS at a stable URL
- [ ] Four environment variables set and visible to the web server
- [ ] `/.well-known/…` routed to PHP
- [ ] Keypair generated, private key `0600`
- [ ] One user, in `editors`

---

## Step 2 — walk the discovery chain by hand

**Do this before touching a client.** Every client failure downstream is one of these five, and a
client will tell you "could not connect" where `curl` tells you which hop broke.

```bash
B=https://mcp.example.com
```

### 2.1 Protected resource metadata

```bash
curl -sS $B/.well-known/oauth-protected-resource/mcp
```

```json
{"authorization_servers":["https://mcp.example.com"],"scopes_supported":["mcp:read","mcp:write"],"resource":"https://mcp.example.com/mcp"}
```

- **404** → step 0 is not done, or `.well-known` is not routed to PHP.
- **`authorization_servers` is not your issuer** → `MCP_ISSUER` is wrong or not reaching PHP.

### 2.2 The challenge on an unauthenticated request

```bash
curl -sS -i -X POST $B/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}'
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="mcp:read mcp:write"
```

**Then fetch the URL inside that header.** If it 404s, discovery is dead at hop one and nothing
downstream matters. This one check catches more than any other.

- **403 instead of 401** → `DnsRebindingProtectionMiddleware` refused the `Host` header.
  `McpServer` builds its allowlist from `MCP_RESOURCE`'s host, so this means the two disagree —
  usually a proxy passing through a different `Host`.
- **`resource_metadata` names the wrong host** → `MCP_RESOURCE` is wrong. It is never taken from the
  request, so the request is not the problem.

### 2.3 Authorization server metadata

```bash
curl -sS $B/.well-known/oauth-authorization-server
```

```json
{
    "issuer": "https://mcp.example.com",
    "authorization_endpoint": "https://mcp.example.com/oauth/authorize",
    "token_endpoint": "https://mcp.example.com/oauth/token",
    "jwks_uri": "https://mcp.example.com/oauth/jwks",
    "revocation_endpoint": "https://mcp.example.com/oauth/revoke",
    "scopes_supported": ["mcp:read", "mcp:write"],
    "response_types_supported": ["code"],
    "response_modes_supported": ["query"],
    "grant_types_supported": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
    "revocation_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
    "code_challenge_methods_supported": ["S256"]
}
```

`"code_challenge_methods_supported": ["S256"]` with no `plain` is the §4.1 tightening, visible to a
client before it sends anything. There is deliberately **no `registration_endpoint`** — see step 3.

### 2.4 JWKS

```bash
curl -sS $B/oauth/jwks
```

```json
{"keys":[{"kty":"RSA","n":"vlq7KiVU-W0LyQP3txwaVW4F…","e":"AQAB","use":"sig","alg":"RS256","kid":"_rYAAPJLJAeXqvvUfG3FRcxGaR3EGmiZ0Y_V7QfSISo"}]}
```

One key, with a `kid`. **There must be no `d` and no `PRIVATE KEY`** — if there is, stop and treat
it as a disclosure incident.

### 2.5 Registration is closed

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST $B/oauth/register
```

```console
404
```

**404 is correct and deliberate** (ADR 0006). Step 3 decides whether to change it.

- [ ] All five responses as above
- [ ] The `resource_metadata` URL from 2.2 fetched successfully

---

## Step 3 — decide how the client gets a `client_id`

A client that has never spoken to this server needs an identifier. There are three routes and
clients differ, so decide before you connect one.

| Route | What you do | When |
|---|---|---|
| **Client ID Metadata Document** | Nothing | The client's `client_id` is its own https URL. On by default |
| **Pre-registration** | `bin/register-client.php` | You know the client and can paste an id into it |
| **Dynamic registration** | Turn it on | The client insists, and you accept the trade |

### 3.1 Get the client's real values — do not guess

Point the client at your server and let it fail. Then read what it actually sent:

```bash
grep 'authorize.refused' $MCP_STORAGE/audit/audit.log | tail -1
```

```json
{"time":"2026-09-04T11:31:12+00:00","event":"authorize.refused","client_id":"…","error":"invalid_client"}
```

The `redirect_uri` is in the web server's access log alongside it:

```bash
grep '/oauth/authorize' /var/log/nginx/access.log | tail -1
```

Use those two values verbatim. Guessing a redirect URI wastes a round trip every time, because
league matches it **exactly** — a trailing slash or a different case is a different URI.

### 3.2 Pre-register

```bash
php examples/blog/bin/register-client.php "MCP Inspector" 'http://localhost:6274/oauth/callback'
```

```console
Registered MCP Inspector
  client_id: iA9Oq7fBvjZBqSQ--pFFaA
  This is a public client: it authenticates with PKCE and holds no secret.
```

Loopback `http://` is accepted on purpose — RFC 8252 §7.3, how desktop clients receive callbacks.

### 3.3 Or turn on dynamic registration

Claude's clients generally attempt DCR. If you would rather let them:

```php
$configuration = new Configuration(
    // …
    endpoints: EndpointUrls::below($issuer, withRegistration: true),
);
```

That single flag makes `registration_endpoint` appear in the metadata document and
`OAuthServer::register()` answer for real.

> **Know what you are turning on.** It is an unauthenticated write endpoint on your credential
> store: anyone who can reach it can create clients, and each one is a file. It is throttled and
> nothing else. ADR 0006 is the reasoning, and it is why this is opt-in rather than default.
>
> The middle path is to enable it, connect the client once, note the `client_id` it was issued, and
> turn it back off.

- [ ] Route chosen, and the client can be identified

---

## Step 4 — MCP Inspector

Inspector first: it shows you the protocol, and it is more forgiving than a production client.

```bash
npx @modelcontextprotocol/inspector
```

1. **Transport type:** Streamable HTTP
2. **URL:** `https://mcp.example.com/mcp`
3. **Connect**

Expect: redirect to `/oauth/authorize` → your login page → the consent screen → back to Inspector.

> Inspector's callback is typically `http://localhost:6274/oauth/callback`, but confirm it from your
> logs (step 3.1) rather than trusting that — it has changed between versions.

### What to look at on the way through

- **The consent screen lists `mcp:read` and `mcp:write`.** These are the scopes that will actually be
  granted — the request narrowed by `ScopePolicy` — not what the client asked for. Drop the user out
  of `editors` and it should show `mcp:read` alone.
- **You are asked to log in even if you already were.** Expected if the application uses
  `voltcms/useraccess`'s `SessionAuth`, which sets `SameSite=Strict`; the client's first hop is a
  cross-site navigation, so the cookie is not sent. The second pass is same-site and works. The
  example's own `Session` uses `Lax` and does not show this.
- **The URL keeps its query string across login.** If `code_challenge` is missing after logging in,
  your login page dropped it — finding F1, and the reason `LoginRedirectorInterface`'s docblock says
  so twice.

### Then exercise the tools

| Call | Proves |
|---|---|
| `tools/list` | Three tools with descriptions and schemas |
| `list_posts` | The happy path |
| `read_post` with `{"slug":"hello-world"}` | Arguments reach the handler |
| `read_post` with `{"slug":"../../bootstrap"}` | Refused — `Posts::pathFor()` matches the listing, not the filesystem |
| `write_post` | Needs `mcp:write`; the interesting one |

- [ ] Full OAuth round trip through a browser
- [ ] All three tools called
- [ ] Traversal slug refused

---

## Step 5 — a real Claude client

### 5.1 Claude Code

```bash
claude mcp add --transport http example-blog https://mcp.example.com/mcp
```

Then `/mcp` inside Claude Code to authenticate. It opens a browser for the same flow.

### 5.2 claude.ai

Settings → Connectors → **Add custom connector** → `https://mcp.example.com/mcp`.

This is the one that needs a genuinely public HTTPS URL and a valid certificate — a tunnel is fine,
a self-signed certificate is not.

### 5.3 What is likely to differ from Inspector

- **Dynamic registration.** If step 3 left it off, expect the connection to fail at registration.
  The audit log names the `client_id` it wanted; pre-register or flip the flag.
- **The `resource` parameter.** Clients following the 2025-06-18 spec send `resource=` on both
  authorize and token. `ResourceIndicator` refuses anything that is not your `MCP_RESOURCE`, exactly
  — including a trailing-slash mismatch. If you see `invalid_target`, compare the two strings
  character by character.
- **Protocol era.** The transport serves both. Check which the client negotiated:
  ```bash
  grep -o '"protocolVersion":"[^"]*"' $MCP_STORAGE/../access.log | tail -1
  ```
  A `2025-*` version means the handshake era, which uses the session store — so
  `SessionStoreFactory`'s directory must be writable and swept.

- [ ] Claude Code connects and calls a tool
- [ ] claude.ai connects and calls a tool

---

## Step 6 — exercise what only a live pass can reach

Each of these is covered by a unit test. What is not covered is a real client's reaction to it.

### 6.1 Refresh after expiry

Leave the connection idle for **over an hour** (the access token TTL), then use a tool. The client
should refresh silently. Confirm:

```bash
grep 'token.issued' $MCP_STORAGE/audit/audit.log | tail -2
```

Two entries: `authorization_code`, then `refresh_token`. A client that instead sends you back through
the browser is not refreshing — check that it stored the refresh token.

### 6.2 Revocation is immediate

Verified live; the next call 401s with no waiting:

```console
$ curl -sS -o /dev/null -w '%{http_code}\n' -X POST $B/oauth/revoke \
    --data-urlencode "token=$TOKEN" --data-urlencode "client_id=$CID"
200
$ curl -sS -o /dev/null -w '%{http_code}\n' -X POST $B/mcp -H "Authorization: Bearer $TOKEN" …
401
```

That is ADR 0005 — validation reads the store on every request.

### 6.3 Rotation does not disconnect

While a client is connected:

```bash
php -r 'require "examples/blog/bootstrap.php"; echo $oauth->keys()->rotate(), "\n";'
```

The existing token must keep working — the retired public key stays in JWKS until the tokens it
signed expire (ADR 0004). Confirm two keys are now published, and that the client picks up the new
one on its next JWKS fetch.

### 6.4 Deactivation kills a live token

Set the user inactive, then call a tool: **401**, immediately. This is `findUser()` returning null on
every validation.

### 6.5 Demotion narrows

Remove the user from `editors` and call again: `read_post` continues, `write_post` stops. Then force
a refresh — `ScopeRepository::finalizeScopes()` re-checks there too, so the new token should not
carry `mcp:write` at all.

### 6.6 Throttle

Post ten bad authorization codes to `/oauth/token` from one address. The eleventh should be **429**
with `Retry-After`. Then confirm a *good* request from a different address still works — buckets are
per endpoint and per peer.

- [ ] Refresh works after real expiry
- [ ] Revocation immediate
- [ ] Rotation does not disconnect
- [ ] Deactivation and demotion take effect
- [ ] Throttle engages and is scoped

---

## Step 7 — record the result and tag

1. **Every bug gets a regression test here**, in the commit that fixes it — PLAN.md §11.
2. **`CHANGELOG.md`** — move `[Unreleased]` to `[0.1.0]` with a date.
3. **`README.md`** — replace the "pre-release, feature-complete" block with what was tested against,
   naming the client versions.
4. **`SECURITY.md`** — drop the pre-release warning, or narrow it to "no independent review".
5. **`PLAN.md` §8** — mark P6 fully done.
6. **Tag:**
   ```bash
   git tag -a 0.1.0 -m "First release: MCP and OAuth 2.1 for flat-file PHP applications"
   git push origin 0.1.0
   ```
7. **Packagist** — submit `voltcms/mcp`, enable the update hook.

- [ ] Regression tests written for anything found
- [ ] Docs updated, `0.1.0` tagged and pushed

---

## Appendix A — failure index

| Symptom | Cause | Fix |
|---|---|---|
| Client: "could not connect", nothing in the logs | `.well-known` not routed to PHP | Step 1.3; verify with 2.1 |
| `/.well-known/oauth-protected-resource/mcp` → 404 | Step 0 not done | Step 0 |
| `403 Forbidden` on `/mcp` | `DnsRebindingProtectionMiddleware` refused the `Host` | `MCP_RESOURCE` host must match the `Host` the client sends |
| `invalid_request`, hint names `code_challenge_method` | Client sent `plain` or omitted it | Not fixable here by design — §4.1. The client must send `S256` |
| `invalid_target` | `resource` parameter ≠ `MCP_RESOURCE` | Compare exactly, including trailing slash |
| `invalid_client` on authorize | Client not registered, or `redirect_uri` differs | Step 3.1 — read the real values |
| Registration → 404 | DCR is opt-in | Step 3.3, or pre-register |
| Consent form submits but re-renders | Ticket did not verify — expired, or the view dropped the hidden field | Render `hiddenFields` verbatim (ADR 0003) |
| Login loop: back to login after signing in | Login page dropped the query string | Preserve `Request::$uri` whole — finding F1 |
| Asked to log in when already logged in | `SameSite=Strict` session cookie | Expected with `SessionAuth`; use `Lax` if it bothers you |
| Everything 401s at once | Store unreadable — a missing record reads as revoked | Check `MCP_STORAGE` permissions. Fail-closed by design |
| `500` with `server_error` | An internal exception; never leaked to the client by design | Read the PHP error log |
| Tokens valid but tools 403 | Scope policy grants nothing | Check the user's groups against `ScopePolicy` |

---

## Appendix B — running the example locally

The whole flow works over loopback, which is the fastest way to test a change. Plain `http` is
accepted for loopback and nowhere else.

```bash
export MCP_STORAGE=/tmp/mcp-live
export MCP_ISSUER=http://localhost:8080
export MCP_RESOURCE=http://localhost:8080/mcp
export MCP_ENCRYPTION_KEY="$(php -r 'echo base64_encode(random_bytes(32));')"

php -S localhost:8080 -t examples/blog/public examples/blog/dev-router.php
```

> **Use `dev-router.php`.** The built-in server has no rewrites, and the two obvious alternatives
> both fail: `-t public` alone never routes `/.well-known/…` to PHP, and passing `public/mcp.php` as
> the router sends *everything* through the front controller — so `/login.php` 404s and the consent
> screen loads unstyled. The router serves real files as files and everything else to the front
> controller, which is what the Apache and nginx rules express.

Then, in a second shell:

```bash
php examples/blog/bin/create-user.php jannis 'correct-horse-battery' editors
php examples/blog/bin/register-client.php "MCP Inspector" 'http://localhost:6274/oauth/callback'
```

Steps 2, 4 and 6 all work against `http://localhost:8080`. Only step 5 needs a public host.
