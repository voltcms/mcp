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

Identity is not on that list, and that is deliberate: `UserAccessIdentityProvider` is concrete.

## Running it

```bash
export MCP_ENCRYPTION_KEY="$(php -r 'echo base64_encode(random_bytes(32));')"
php -S localhost:8080 -t examples/blog/public
```

Then point `issuer` and `resource` in `bootstrap.php` at `http://localhost:8080` and
`http://localhost:8080/mcp` — plain HTTP is accepted for loopback and nowhere else.

The built-in server has no rewrite rules, so `/.well-known/...` will 404. In front of Apache or
nginx, use the snippets in the root README.

Create a user and put them in the `editors` group with `voltcms/useraccess`'s own tooling, register
a client, and connect:

```bash
php examples/blog/bin/register-client.php "MCP Inspector" http://localhost:6274/oauth/callback
```

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
