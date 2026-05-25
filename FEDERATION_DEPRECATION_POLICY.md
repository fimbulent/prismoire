# Federation deprecation policy

This file is the operator-facing summary of Prismoire's federation
compatibility commitments.

## What we promise

### Signed-object formats: forever

Once Prismoire has issued an Ed25519 signature over canonical bytes
in a given format version, every conformant Prismoire build verifies
that signature **forever**. We never retire a signed-payload format
version. Old signed objects in your DB stay verifiable across every
future upgrade.

Reason: a signature commits the signer to specific bytes. We cannot
ask a user from three years ago to re-sign their post under a new
format, so the verifier code path for the old format has to stay.
The carrying cost is small; the alternative is breaking history.

### Federation transport (protocol versions): 12-month floor

When we ship a new federation protocol version (`v1`, `v2`, …) we
commit to keeping the previous version's transport — its routes,
headers, envelope semantics, capability shapes — usable for at least
**12 months after the first stable release tag of the new version**.

The 12-month clock:
- **Starts** at the first stable release tag of vN+1 (e.g. `v2.0.0`).
  Pre-release tags like `v2.0.0-rc.1`, `v2.0.0-beta.3` do **not**
  start the clock.
- **Is anchored to the release tag**, not to the day any particular
  peer adopts vN+1. If you upgrade late, you don't get an extended
  window. Operators who upgraded on day one will start dropping vN
  traffic 12 months later regardless.
- **Is a floor, not a target.** Many deprecations will run longer in
  practice.

### Capability removal: one minor release, dual-channel

A specific federation capability within a protocol version can be
removed earlier than the protocol-version sunset, but never without:

1. A wire signal — the capability appears in `deprecated_capabilities`
   on the deprecating peer's `GET /federation/v1/identity` response,
   carrying a `sunset_at` Unix-ms timestamp. Operator dashboards
   should surface this automatically.
2. A release-notes entry on the deprecating implementation,
   describing rationale, replacement (if any), migration guidance,
   and the same `sunset_at` value.

`sunset_at` must be at least one minor release after the release that
first advertised the deprecation. Beyond that floor, the deprecating
peer chooses its own timeline based on its operator population.

## What this means for you as an operator

- **You don't have to upgrade on day one of a new protocol version.**
  You have at least 12 months from the vN+1 release tag before
  upgraded peers can stop federating with you on vN. Plan against
  that anchor (it's published, calendar-fixed) rather than against
  your peers' adoption schedules.
- **Your stored data is never at risk from a protocol upgrade.**
  Signature formats never retire. Upgrading a Prismoire instance
  does not invalidate any previously-stored signed object.
- **Watch your dashboards for `deprecated_capabilities`.** When peers
  you federate with advertise a capability under
  `deprecated_capabilities`, your dashboard should call it out. The
  `sunset_at` timestamp is the earliest moment that peer may stop
  honoring it; plan migrations against that absolute date.
- **The compatibility matrix is the operational truth.** If you need
  to know the actual scheduled sunset date for a specific protocol
  version, check the documented compatibility matrix. That table
  records the real per-version dates, which may be later than the
  12-month floor but never earlier.

## What we don't promise

- **No reverse signal.** There is no wire mechanism for you to tell
  peers "I depend on this capability." Dependencies are tracked
  locally and inferred from your federation traffic, not declared
  over the wire.
- **No long-tail forever-support for transport.** Unlike signed
  formats, federation transport versions do retire. If you stay on
  vN past its sunset date you can still run a local Prismoire
  instance, but vN+1-only peers will stop federating with you.
- **No grace period beyond the published floor for late adopters.**
  The 12-month clock is anchored to the protocol-version tag date.
  Operators who upgrade late get a shorter effective window in which
  to keep accepting vN traffic.
