# voltcms/mcp

**MCP and OAuth 2.1 for flat-file PHP applications — no identity provider, no database, no
daemon.**

A personal blog on shared hosting should not need Keycloak to talk to a Claude session. This
package lets one speak the Model Context Protocol to a remote client — a Claude session, a
ChatGPT session, Claude Code — with a real OAuth 2.1 authorization server backed by nothing
but files on disk.

> ### Status: pre-release, under construction
>
> The plan and both spike-backed decision records are complete; the implementation is being
> built out phase by phase (see [`PLAN.md`](PLAN.md) §8). **Nothing here is released yet, and
> the API shown below is the intended shape, not a shipped one.** Do not put this in front of
> real credentials until `0.1.0` is tagged.

---

## What it actually is

Three mature packages do the heavy lifting; this one is the glue nobody else has.

| Layer | Provided by |
|---|---|
| MCP protocol, both eras, HTTP transport, tools | [`mcp/sdk`](https://packagist.org/packages/mcp/sdk) |
| Token issuance: codes, PKCE, refresh rotation | [`league/oauth2-server`](https://oauth2.thephpleague.com/) |
| Users, groups, sessions, flat-file store, locking, throttle, audit | [`voltcms/useraccess`](https://packagist.org/packages/voltcms/useraccess) |
| **Everything between them** | **`voltcms/mcp`** |

That last row is the reason this repository exists: FileDB-backed OAuth repositories, an
S256-only guard and RFC 8707 audience binding that `league` cannot be configured into, RFC
8414 authorization-server metadata that `league` does not ship, the consent seam, Client ID
Metadata Documents, signing-key management, and the bridge that hands `mcp/sdk` a validator
for the tokens `league` minted.

`mcp/sdk` will never do this part: its own
[ADR](https://github.com/modelcontextprotocol/php-sdk) rules an authorization server
permanently out of scope — "no token issuance, no token signing or key management, no login
UI, no consent UI, no authorization-code or refresh-token storage" — and points at an external
IdP or `league/oauth2-server` in your own application instead. This package is that second
option, written once.

## Requirements

- PHP 8.2, 8.3 or 8.4, with `ext-json` and `ext-openssl`
- A writable directory **outside the web root** for the token store and the signing key
- HTTPS (the MCP authorization spec requires it; `localhost` is exempt for development)

## Install

```bash
composer require voltcms/mcp
```

A PSR-17 factory is needed for the HTTP transport; `nyholm/psr7` is the recommended one:

```bash
composer require nyholm/psr7 nyholm/psr7-server
```

## A worked example

*(Intended API — see the status note above.)*

Configuration is explicit on purpose. The issuer URL is never derived from `$_SERVER`, because
`Host` is attacker-controlled and a forged one would publish an attacker's origin as your
authorization server.

```php
use VoltCMS\MCP\Configuration;

$config = new Configuration(
    issuer:           'https://example.com',
    resource:         'https://example.com/mcp',
    storageDirectory: '/var/private/example.com/mcp',
    privateKeyPath:   '/var/private/example.com/mcp/keys/private.key',
    publicKeyPath:    '/var/private/example.com/mcp/keys/public.key',
    encryptionKey:    getenv('MCP_ENCRYPTION_KEY'),
    scopes:           ['mcp:read', 'mcp:write'],
);
```

Your application supplies its tools, its consent markup and its content directories. Nothing
else:

```php
$mcp = new McpServer($config, $identity, tools: [
    new ReadPost($content),
    new ListPosts($content),
]);

$response = $mcp->handle(Request::fromGlobals());   // returns; never echoes
```

Every handler in this package **returns** a response and never writes to the output buffer, so
your application keeps its single output chokepoint and the whole package is testable without
a web server.

The two things you implement are your own markup and your own login page — neither is a
security decision:

```php
interface ConsentViewInterface
{
    public function render(ConsentRequest $request): Response;
}

interface LoginRedirectorInterface
{
    public function redirectToLogin(Request $request): Response;
}
```

> **One trap, from a real integration.** Your login flow must preserve the pending request
> across the round trip. Redirecting to the current path *without* its query string silently
> discards the entire authorization request — `client_id`, `redirect_uri`, `state`,
> `code_challenge` and all.

Identity is not on that list. If you already use `voltcms/useraccess`, pass it your `users/`
and `groups/` directories and you are done — `UserAccessIdentityProvider` is concrete.
`IdentityProviderInterface` is there for applications with a different user store.

## Serving the `.well-known` documents

This package renders the metadata documents; routing them is deployment, and every host
differs. Both the authorization-server metadata (RFC 8414) and the protected-resource metadata
(RFC 9728) live under `/.well-known/`, which most setups will not route to PHP by default.

**Apache** (`.htaccess` at the document root):

```apache
RewriteEngine On
RewriteRule ^\.well-known/oauth-authorization-server/?$ /mcp.php?doc=as [L,QSA]
RewriteRule ^\.well-known/oauth-protected-resource/?$   /mcp.php?doc=pr [L,QSA]
```

**nginx**:

```nginx
location = /.well-known/oauth-authorization-server { rewrite ^ /mcp.php?doc=as last; }
location = /.well-known/oauth-protected-resource   { rewrite ^ /mcp.php?doc=pr last; }
```

Some hosts ship a literal `.well-known/` directory that shadows these rules — check that the
document is actually served by PHP before debugging anything else.

## When to use an external IdP instead

Honestly: often.

Use Keycloak, Auth0, Entra or Okta — with `mcp/sdk`'s `OAuthProxyMiddleware`, and skip this
package — if **any** of these are true:

- You have more than a handful of users, or users who are not you.
- You need SSO, MFA, or an account lifecycle someone else administers.
- You need instant revocation of an access token. Ours are JWTs with a one-hour TTL;
  revoking the *grant* is immediate, revoking an already-issued access token is not
  (see [`SECURITY.md`](SECURITY.md)).
- You have a database and an operations story, so "no daemon" buys you nothing.
- Your compliance regime expects an audited identity product.

This package is for the other case: a single-tenant, self-hosted PHP application on shared
hosting, where standing up an identity provider costs more than the feature is worth.

## Documentation

- [`PLAN.md`](PLAN.md) — architecture, security posture, testing strategy, delivery phases
- [`docs/decisions/0001-build-vs-adopt.md`](docs/decisions/0001-build-vs-adopt.md) — why we
  adopt `mcp/sdk` rather than write a protocol layer
- [`docs/decisions/0002-wrap-or-write.md`](docs/decisions/0002-wrap-or-write.md) — why we wrap
  `league/oauth2-server` rather than write a token issuer
- [`SECURITY.md`](SECURITY.md) — what this package guarantees, and what it does not
- [`CLAUDE.md`](CLAUDE.md) — coding standards and the invariants that must not be simplified away

## License

MIT. See [`LICENSE`](LICENSE).
