# examples/blog — the whole flow, end to end

A blog with three MCP tools and a real OAuth 2.1 authorization server, in about 350 lines of
application code. It is the shape PLAN.md §1 describes: *a consuming application supplies its tools,
its consent markup and its content directories, and nothing else.*

## The files, and which of them are yours

| File | What it is |
|---|---|
| `bootstrap.php` | Configuration and wiring. The only file that knows this package exists. |
| `public/mcp.php` | One front controller. Routes, then emits — eleven lines at the bottom. |
| `public/login.php` | **Yours.** The application's own login page; not part of this package. |
| `src/ConsentView.php` | **Yours.** One of the two interfaces you implement. Markup, not security. |
| `src/LoginRedirector.php` | **Yours.** The other one. Read its docblock before writing your own. |
| `src/Session.php` | **Yours**, unless you use `voltcms/useraccess`'s `SessionAuth`, in which case pass `Identity\UserAccessSession` and delete it. |
| `src/Posts.php` | **Yours.** The tools. Plain methods with real type declarations. |
| `bin/maintenance.php` | The cron entry. There is no daemon; sweeping is yours to schedule. |
| `bin/register-client.php` | Registering a client by hand. |
| `bin/create-user.php` | Creating an account, because `voltcms/useraccess` ships no CLI. |
| `dev-router.php` | Rewrite rules for PHP's built-in server. Local development only. |

Identity is not on that list, and that is deliberate: `UserAccessIdentityProvider` is concrete.

## Running it

Four environment variables, and a router. Plain HTTP is accepted for loopback and nowhere else.

```bash
export MCP_STORAGE=/tmp/mcp-live
export MCP_ISSUER=http://localhost:8080
export MCP_RESOURCE=http://localhost:8080/mcp
export MCP_ENCRYPTION_KEY="$(php -r 'echo base64_encode(random_bytes(32));')"

php -S localhost:8080 -t examples/blog/public examples/blog/dev-router.php
```

`dev-router.php` is not decoration. The built-in server has no rewrite rules, and the two obvious
things to try both fail: `-t public` alone never routes `/.well-known/…` or `/oauth/…` to PHP at
all, and passing `public/mcp.php` as the router sends *everything* through the front controller, so
`/login.php` 404s and the consent screen loads unstyled. The router serves real files as files and
everything else to the front controller — which is exactly what the Apache and nginx rules in the
root README express.

Then, in a second shell, create a user and a client:

```bash
php examples/blog/bin/create-user.php jannis 'correct-horse-battery' editors
php examples/blog/bin/register-client.php "MCP Inspector" 'http://localhost:6274/oauth/callback'
```

The group name matters: `bootstrap.php` maps `editors` to `mcp:read mcp:write` and gives every other
account `mcp:read` alone, so it is what makes `write_post` work.

Connect MCP Inspector to `http://localhost:8080/mcp`, or walk the discovery chain by hand — both are
written out step by step in [`docs/release-checklist.md`](../../docs/release-checklist.md).

## What to look at

**`bootstrap.php` has no `$_SERVER['HTTP_HOST']` in it.** The issuer and the resource are
configured. A forged `Host` header on a request for the metadata document would otherwise publish an
attacker's origin as this site's authorization server, and the client would send its authorization
request there (PLAN.md §4.3).

**`ConsentView` shows `$request->scopes`, not what the client asked for.** They are the same list
only when the user's roles support everything requested. A consent screen showing the request would
ask the user to approve something the token will not carry.

**`ConsentView` renders `$request->hiddenFields` verbatim.** That is the signed ticket binding the
approval to this user, this client and these scopes. A template that drops it never approves
anything — which is the failure mode we want (`docs/decisions/0003-consent-seam.md`).

**`LoginRedirector` hands back `$request->uri`, query string and all.** Redirecting to the path
alone discards the entire authorization request, and the client sees a parameterless error after a
login that appeared to work. It is finding F1 from the first real integration.

**`Posts::pathFor()` matches the slug against the listing instead of concatenating it into a path.**
A tool argument is attacker-influenced — it arrives from a model, over the network — and
`../../config` is a slug something will ask for eventually.

**`public/mcp.php` is the only file that emits anything.** Every handler in the package returns a
response; nothing echoes, sets a header, or exits.
