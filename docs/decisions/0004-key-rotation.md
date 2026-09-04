# 0004 — Key rotation: manual, thumbprinted, with the retired public key kept for one token TTL

- **Status:** Accepted
- **Date:** 2026-09-04
- **Answers:** PLAN.md §10 open question 1 — "key lifetime, overlapping keys in JWKS, manual or
  age-triggered"
- **Phase:** P4

## Context

Access tokens became JWTs when decision 0002 wrapped `league/oauth2-server`, which brought key
management with it. PLAN.md §4.6 called this "real work the opaque design avoided" and left the
policy open.

Three sub-questions, and the first two answer the third.

**How long does a key live?** There is no operational answer for this deployment shape. A blog on
shared hosting has no HSM, no key ceremony and no one to notice an expiry date. Any lifetime this
package picked would be a number nobody checked.

**What happens to tokens signed by the outgoing key?** They stay valid — they were correctly signed
when they were issued, and nothing about a new key makes them wrong. A rotation that deleted the
old public key would reject every live token and disconnect every client, which turns "rotate the
key" into "log everyone out". Nobody would run it twice.

**Who triggers a rotation?** There is no daemon. There is no scheduler this package can rely on.
An age-triggered rotation would have to fire from inside a web request, which means a request that
occasionally does key generation — a second or two of RSA work on shared hosting, at random, for
whichever visitor is unlucky.

## Decision

**Rotation is a method, not a schedule.** `KeyManager::rotate()` is called by the deployment — from
a cron entry, from a deploy script, from a one-line CLI file. The README shows the cron line.
`ensureKeyPair()` is the only thing safe to call per-request, and it does nothing once the files
exist.

**The retired public key is kept, and published, until the last token it could have signed has
expired.** That is `accessTokenTtl` after the rotation, plus five minutes of clock-skew grace. The
retired key goes into `retired/` beside the private key, named by its expiry, and is deleted by
`purgeRetiredKeys()` — which `rotate()` calls, so the ring cannot grow without someone rotating.

**The retired PRIVATE key is not kept.** Nothing signs with it again; keeping it would be a
liability with no use. Rotation overwrites it.

**`kid` is the RFC 7638 JWK thumbprint**, derived from the key itself rather than assigned. A key
therefore has the same identifier wherever it is published, a rotation cannot accidentally reuse
the previous identifier, and two servers publishing the same key agree on its name without
coordinating. Every issued token carries the `kid` header, which is what lets a consumer pick the
right key out of a JWKS that is publishing two.

## Consequences

- A deployment that never rotates is no worse off than one using a static key, which is where it
  would have been anyway. A deployment that does rotate loses nothing: clients keep working across
  the rotation and pick up the new key on their next JWKS fetch.
- The JWKS cache window (10 minutes) is deliberately far shorter than the retirement grace (one
  hour plus five minutes), so a client holding a stale key set has time to refresh before the key
  it is missing is needed.
- Rotating twice inside the token TTL publishes three keys. That is correct — tokens from both
  retired keys are still live — and bounded, because the oldest is dropped as soon as its window
  closes.
- Two rotations in the same second produce two retired keys with the same expiry. The retired-key
  index is keyed by path rather than by expiry so neither is silently dropped; a collision there
  would have discarded a key that was still verifying live tokens.
- Key files are written to a temporary name, `chmod`'d, and renamed. A reader never sees a
  half-written key, and a private key is never briefly world-readable between `file_put_contents()`
  and `chmod()`.
- There is no key escrow, no recovery, and no re-issuance. Losing the private key file means every
  live access token stops verifying; the fix is to let clients re-authorize. For this deployment
  shape that is the right trade — the alternative is a backup of a signing key, which is a worse
  problem than the one it solves.
