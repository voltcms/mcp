# 0003 — The consent seam: a stateless signed ticket, not a session

- **Status:** Accepted
- **Date:** 2026-09-04
- **Follows:** `0002-wrap-or-write.md`, which wrapped `league/oauth2-server` for issuance and
  left the authorize endpoint's user-facing half unspecified
- **Phase:** P3

## Context

`league/oauth2-server` deliberately stops one step short of the authorize endpoint. It hands back
an `AuthorizationRequest`, and the integrator is expected to call `setUser()` and
`setAuthorizationApproved()` before calling `completeAuthorizationRequest()`. Its own examples do
this from a session and leave everything between as an exercise.

Three things have to be decided in that gap, and only the first is obvious:

1. **Who renders the consent screen.** Settled by PLAN.md §3.1: the consumer, through
   `ConsentViewInterface`. This package has no markup and no stylesheet, and should not grow one.
2. **How the endpoint knows a decision has been made.** The endpoint completes on a POST, so
   something has to distinguish "the user pressed Approve" from "a page the user was visiting
   submitted a form at us".
3. **Where that something lives.** This package has no session of its own. It cannot start one
   without colliding with the consuming application's, and it has no daemon to expire one.

Point 2 is not a hypothetical. An authorize endpoint that completes on any authenticated POST is a
CSRF hole with an unusually bad payload: the attacker does not get one action, they get an
authorization code, and with it a refresh token and a month of access.

## Options considered

**A. Require the consumer to supply the decision.** `handle(Request $request, bool $approved)`.
Simple for us, and it moves the entire CSRF question onto the consumer — who is implementing a
consent screen for the first time, once, and has no reason to know the shape of the attack. The
one interface a consumer must fill would become a security interface, which PLAN.md §3.1
explicitly does not want.

**B. Hold pending authorization requests in the store.** Write a record at GET, look it up at POST.
Works, and gives somewhere to hang a "remember this approval" feature later. But it puts a
write on an unauthenticated GET — anyone can fill the collection — and needs a sweeper the
deployment does not have. It also makes the consent screen stateful for no benefit the flow needs:
everything about the request is already in the query string.

**C. Sign the decision's context and carry it in the form.** No storage, no session. The endpoint
computes a binding from the request it is handling, HMACs it with an expiry, and puts the result in
a hidden field. On POST it recomputes the binding from the request it is *then* handling and
compares.

## Decision

**Option C.** `ConsentTicketSigner` issues and verifies a ticket of the form
`<expiry>.<hmac-sha256>` over:

| Field | Why it is in the binding |
|---|---|
| `user_id` | A ticket minted for one logged-in user must not approve for another. This is what makes the ticket a CSRF token: the attacker cannot mint one carrying the victim's id. |
| `client_id` | Approving Claude Desktop must not approve a client the user has never seen. |
| `redirect_uri` | Approving a redirect back to the client must not approve a redirect elsewhere. |
| `scopes` | The *granted* scopes, already narrowed by the policy — approving `mcp:read` must not approve `mcp:write`. |
| `code_challenge` | An approval is for one PKCE exchange, not for a challenge substituted afterwards. |
| `state` | Kept whole so the round trip is exactly the one that was shown. |
| `resource` | The audience the token will carry. |

The signing key is `Configuration::$encryptionKey` — the key league already uses to encrypt
authorization codes and refresh tokens. A deployment that leaks it has lost the ability to protect
codes, so protecting consent with a second key would guard the smaller thing.

The TTL is 15 minutes. Long enough to read a consent screen and think; short enough that a ticket
recovered from a browser's history or a proxy log is worthless.

A POST whose ticket does not verify is answered by **re-rendering the consent screen**, not by an
error. An expired ticket and a forged submission are indistinguishable from inside the endpoint,
and re-asking is the right answer to both.

## Consequences

- A consent view that drops the hidden fields never approves anything. That is the failure mode we
  want: a broken template refuses, rather than accepting whatever arrives.
- There is **no "remember this approval"**. Every authorization asks. Option B would have given us
  one; if it is ever wanted, it is a store on top of this, not instead of it.
- `ConsentRequest::$formAction` needs an absolute URL for the authorize endpoint, which
  `Configuration` did not have. It now carries the five endpoint URLs, supplied through the new
  `EndpointUrls` value object and defaulted to `<issuer>/oauth/…`. RFC 8414 metadata needs the same
  five in P4, so this is not a cost the consent seam pays alone. They are configuration, and never
  derived from a request header, for the reason PLAN.md §4.3 gives.
- The scopes on the consent screen are the ones that will be granted, not the ones requested. A
  screen showing the request would ask the user to approve something the token will not carry.
- `ConsentTicketSigner` sorts the binding before signing, so a caller cannot change the signature by
  reordering what it passes. Otherwise "the same approval, in a different order" would read as a
  forgery, and the bug would only surface once someone refactored the endpoint.
