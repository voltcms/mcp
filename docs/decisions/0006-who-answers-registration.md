# 0006 — Client ID Metadata Documents answer for unknown clients; dynamic registration is opt-in

- **Status:** Accepted
- **Date:** 2026-09-04
- **Answers:** PLAN.md §10 open question 3 and §4.4 — "`mcp/sdk` *does* ship DCR middleware and so
  might we; exactly one must answer"
- **Phase:** P6

## Context

An MCP client that has never talked to this server needs a `client_id` before it can start an
authorization request. There are three ways it can get one, and §4.4 left the choice open because
it could only be made against a working server.

1. **Somebody registers it by hand.** Fine for the deployment this package targets — a personal
   site with one or two clients — and useless for a client the owner has not met yet.
2. **Dynamic client registration (RFC 7591).** The client POSTs its metadata and is issued an
   identifier. This is what `mcp/sdk` ships middleware for.
3. **Client ID Metadata Documents.** The `client_id` *is* an https URL; the server fetches the
   document there and reads the client's metadata out of it. No registration, no state, and it is
   what the 2026-07-28 MCP specification prefers.

The question §4.4 actually poses — who answers DCR, us or the SDK — turned out to have an easy
answer once the code existed, and to be the less interesting half.

## What the SDK's middleware actually is

`ClientRegistrationMiddleware` belongs to the SDK's **OAuth proxy** story. Reading it:

- It delegates to a `ClientRegistrarInterface` whose job is registering a client with an
  **upstream** identity provider. There is no upstream here; this package *is* the authorization
  server, and a registered client has to land in `ClientRepository`.
- It rewrites `/.well-known/oauth-authorization-server` responses on the way out, to add
  `registration_endpoint`. This package renders that document itself, from `Configuration`, in
  `MetadataEndpoint`. Installing the middleware would give one document two authors.
- It sits on the **MCP endpoint's** middleware stack. Registration belongs on the authorization
  server's routes, beside authorize and token — which in this package are not the same endpoint and
  need not even be on the same host.

So: **this package answers registration; the SDK's middleware is not installed.** That resolves
§4.4 as stated.

## The more important half: registration is off by default

An open registration endpoint is an **unauthenticated write endpoint on the credential store.**
Anyone who can reach it can create clients, and on a flat-file store each one is a file. There is no
row limit, no rate limit beyond the throttle, and no operator watching. For the deployment this
package exists for — a personal site on shared hosting — that is a real liability offered in
exchange for a capability the owner may never use.

And it is a capability that now has an alternative. Option 3 does the same job — accepting a client
this server has never met — with no write at all: the client's identity lives on the client's own
host, this server fetches it, caches it, and issues nothing. `ClientIdMetadataFlowTest` runs that
end to end.

So:

- **CIMD is on by default.** `ClientRepository::getClientEntity()` resolves a `client_id` that is an
  https URL through `ClientIdMetadataResolver`.
- **DCR is off by default.** `EndpointUrls::below()` gives registration no URL unless asked
  (`withRegistration: true`), `Configuration::$registrationEndpoint` is then null, the RFC 8414
  document does not advertise it, and `OAuthServer::register()` answers 404 — the same thing an
  unrouted path would say, because that is what it is.
- A deployment with a reason for DCR passes one flag and takes it on knowingly.

## Consequences

- **Fetching a URL an unauthenticated caller chose is the new exposure**, and it is a real one:
  server-side request forgery aimed at `169.254.169.254`, at `127.0.0.1`, at a neighbour on
  `10.0.0.0/8`. `SsrfGuard` resolves the host itself and inspects the *address*, because
  `metadata.attacker.example` resolving to a link-local address is the whole attack and no hostname
  filter catches it. Its residual limit — DNS answering differently between the check and the
  connection — is closed with `CURLOPT_RESOLVE` when `ext-curl` is present, and documented when it
  is not.
- **Both successes and refusals are cached.** Without caching refusals, `?client_id=https://victim
  .example/…` repeated a few times a second makes this server an amplifier pointed at somebody else.
  Refusals expire sooner than successes, so a client that fixes its document is not locked out for
  an hour.
- **A stored client wins over a document at the same identifier.** Deactivating a client is
  therefore final: it cannot re-admit itself by serving a document at its own URL.
- **A CIMD client is always public.** It never registered, so it holds no secret, and a document
  claiming `token_endpoint_auth_method` other than `none` is refused rather than quietly downgraded.
- **The document's `client_id` must equal the URL it came from.** Without that check,
  `https://attacker.example/client.json` could serve a document claiming to be Claude, and the user
  would approve a consent screen naming Claude while the code went elsewhere. It is the first thing
  `ClientIdMetadataDocument` checks and the one its tests lead with.
- Registered and document-identified clients are validated by **the same code**: `RegisterEndpoint`
  runs its `redirect_uris` through `ClientIdMetadataDocument`. Two sets of rules would be two
  chances to get one of them wrong.
