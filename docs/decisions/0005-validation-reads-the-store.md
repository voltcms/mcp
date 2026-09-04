# 0005 — Token validation reads the store, so revocation is immediate

- **Status:** Accepted
- **Date:** 2026-09-04
- **Answers:** PLAN.md §10 open question 2 — "accept FileDB's O(n) lookup with a documented ceiling,
  or build a purpose-built token store from the start? Leaning: accept, measure, revisit."
- **Supersedes:** the "access-token revocation is not instant" caveat as PLAN.md §5 and
  `SECURITY.md` originally stated it
- **Phase:** P5

## Context

PLAN.md §5 wrote the JWT trade-off down honestly:

> Access tokens are JWTs with a one-hour TTL. They are self-contained and readable by anyone
> holding one, and revoking an access token before it expires is not instant **unless a store
> lookup runs on every request**.

That sentence was written before there was a validator. Building `Bridge\McpTokenValidator` forced
the question it had left open, because the validator was going to read the store anyway — PLAN.md
§5's other promise, that "scopes are re-checked against the live user record on every validation",
means an identity lookup per request whatever else happens. Adding the token record to that is one
more read, not a new category of work.

Against it: §4.5 established that FileDB cannot use an OAuth identifier as a document id, so every
lookup in this package is a `readAll()` plus a scan. Making that scan mandatory on the hot path is
exactly the O(n) the open question was worried about.

So: measure it.

## What was measured

`FileDB::readAll()` plus a `hash_equals()` scan over an access-token collection, worst case (the
record wanted is the last one reached), PHP 8.4.19 on Linux, 20 iterations averaged. Records are
the real shape this package writes — `oauth_id`, `client_id`, `user_id`, `scopes`, `expires_at`,
`revoked` — at 345 bytes each.

| Records | Collection size | Scan, worst case |
|---:|---:|---:|
| 10 | 3.4 KB | 0.05 ms |
| 100 | 34 KB | 0.45 ms |
| 500 | 172 KB | 2.55 ms |
| 1 000 | 345 KB | 5.24 ms |
| 5 000 | 1.7 MB | 36.56 ms |

Linear, as expected, at roughly 5 ms per thousand records.

The number that matters is not the slope but where a real deployment sits on it. Access tokens live
one hour. A client that refreshes on expiry issues 24 tokens a day. `purgeExpired()` run nightly
therefore leaves the collection holding about a day's issuance: **24 records per active client**.
Ten clients is 240 records — a quarter of a millisecond. To reach the 5 ms row a deployment would
need forty active clients and no sweep at all; to reach the 36 ms row, two hundred, which is not
the deployment shape this package is for. And a deployment that gets there has an answer available
before it needs a new store: sweep hourly instead of nightly, and the collection holds an hour's
issuance rather than a day's.

## Decision

**Validation reads the store.** `McpTokenValidator` checks `isAccessTokenRevoked()` on every
request, and a revoked access token stops working at once rather than at expiry.

**PLAN.md §10 question 2 is answered "accept".** FileDB stays. The ceiling is documented above, the
mitigation is `purgeExpired()`, and the trigger for revisiting it is a deployment whose token
collection stays in the thousands with a sweep in place — which is the point at which this package
is being used for something it was not built for.

## Consequences

- `SECURITY.md`'s "what this package does not guarantee" section loses its first entry and gains a
  narrower one. Revocation is immediate; what remains true is that **a token already in flight is
  not recalled**, and that anyone holding a token can read its claims.
- The refusal is fail-closed by construction: `FileDbRepository::isRevoked()` treats an absent
  record as revoked, so a store that has been emptied, moved or made unreadable rejects every token
  rather than accepting every token. An outage, not a bypass — the right direction, and worth
  knowing about before it happens.
- The check costs a scan per MCP request. It is on the same order as the identity lookup that was
  already there, and both are dwarfed by anything the tools themselves do.
- Every refusal from the validator returns the same body, whichever check failed. A caller that
  could tell "expired" from "revoked" from "no such account" apart would have a small oracle over
  tokens it does not hold.
- The README's "when to use an external IdP instead" loses "you need instant revocation of an
  access token" as a reason. It keeps every other one.
