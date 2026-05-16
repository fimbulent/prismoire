# Signed-payload test-vector corpus

Frozen fixtures used by `server/tests/signed_payload_fixtures.rs` to
regression-test the canonical CBOR encoder, parser, and Ed25519
verifier. See `docs/signed-payload-format.md` §8 for the spec.

## Layout

- `post-rev/`, `retract/`, `trust-edge/` — positive fixtures. Each
  named fixture (`<name>.{cbor,sig,key.pub,key.sec}`) holds:
  - `.cbor` — canonical CBOR payload bytes (what gets signed)
  - `.sig` — 64-byte Ed25519 signature over `.cbor`
  - `.key.pub` — 32-byte Ed25519 public key (verifier input)
  - `.key.sec` — 32-byte Ed25519 private-key seed (regeneration only)
- `negative/` — hand-crafted `.cbor` files that fail one specific
  canonicalization or schema check. Expected error class is in
  `NEGATIVE_FIXTURES` in the test file.

## Test-only keys

The `.key.sec` files contain pinned Ed25519 private-key seeds whose
sole purpose is to regenerate this corpus deterministically. **Never
use a corpus key for anything else.** They are not secrets.

## Regenerating

```sh
cargo test -p prismoire-server --test signed_payload_fixtures regen_corpus -- --ignored --nocapture
```

The regenerator is gated behind `--ignored` so it doesn't run on
normal `cargo test`. Run it whenever you add a new fixture descriptor
or rotate a pinned seed; review the resulting diff carefully — a byte
change in an existing fixture means the canonical encoder's output
changed, which is a federation-breaking event under the §1.2
ratchet.

## What's not here

- **CBOR diagnostic notation (`.diag`).** Not currently generated.
  Use `cbor2diag.rb` or `cbor.io`'s diagnostic viewer if you need a
  human-readable view of a `.cbor` file.
