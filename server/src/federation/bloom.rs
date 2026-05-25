//! `prismoire-bloom-v1` Bloom filter family
//! (`docs/federation-protocol.md` §8.2).
//!
//! This is the wire-format-stable filter used by the §8 frontier sync
//! routes. Every implementer on every side of the federation must
//! produce byte-for-byte identical filters from the same key set, so
//! the family pins down every degree of freedom that a generic bloom
//! crate would leave open:
//!
//! - **Hash function** — SipHash-2-4 (via the [`siphasher`] crate),
//!   keyed with the two protocol-mandated 128-bit constants `K_A`
//!   and `K_B` defined below. The choice of SipHash gives us a fast,
//!   cryptographically-keyed PRF whose two-key construction is
//!   exactly what Kirsch–Mitzenmacher double-hashing needs.
//! - **Hash combination** — `bit_i(x) = (h_a(x) + i * h_b(x)) mod m`
//!   for `i ∈ [0, k)`. The arithmetic is done at `u64` width with
//!   wrapping multiply / add before the final `mod m`; this matches
//!   the standard Kirsch–Mitzenmacher derivation and is the
//!   convention every existing implementation lands on. Two filters
//!   that disagree on the wrap-vs-saturate question would produce
//!   different bit positions even with the same `K_A` / `K_B`, so
//!   the convention is documented here even though §8.2 doesn't
//!   spell it out.
//! - **Bit ordering** — MSB-first within each byte:
//!   `bytes[p / 8] >> (7 - (p % 8)) & 1`. The opposite (LSB-first)
//!   is the more common default in off-the-shelf bloom crates,
//!   which is one of the reasons we keep this hand-rolled.
//! - **Wire shape** — the filter is exactly `m / 8` bytes;
//!   `m` is a multiple of 64 in `[64, 2^32)`; `k` is in `[1, 32]`.
//!   The `FilterSpec` CBOR encoding lives in [`crate::federation::frontier`]
//!   alongside the announce/delta types it composes into.
//!
//! What this module does *not* own: the wire CBOR for `FilterSpec`,
//! `FrontierAnnounce`, `FrontierDelta`, or `FrontierSnapshot`. Those
//! all live in `frontier.rs` so the wire types stay co-located. This
//! module is the pure-function core that the wire layer wraps.

use std::hash::Hasher;

use siphasher::sip::SipHasher24;

/// Family name advertised on the wire (§8.2). Every `FilterSpec`
/// produced by this build carries this exact string; receivers
/// reject any other family with `unsupported_family` (§8.3).
pub const FAMILY: &str = "prismoire-bloom-v1";

/// First SipHash-2-4 key, per §8.2. The 128-bit constant
/// `0x0123456789abcdef_0123456789abcdef` is split into two `u64`
/// halves for [`SipHasher24::new_with_keys`]; both halves carry the
/// same byte pattern so the high/low assignment convention is
/// observationally inert here (and equally for [`K_B`]). Documenting
/// it anyway so a future key rotation doesn't accidentally reverse
/// the order.
const K_A: (u64, u64) = (0x0123456789abcdef, 0x0123456789abcdef);

/// Second SipHash-2-4 key, per §8.2. See [`K_A`] for the byte-order
/// note.
const K_B: (u64, u64) = (0xfedcba9876543210, 0xfedcba9876543210);

/// Inclusive lower bound on `m` (the filter bit count). The
/// maximally-permissive sentinel filter (§8.8: `m = 64, all bytes
/// 0xFF`) sits exactly on this boundary, so this constant is also
/// the minimum-allowed value, not a defensive cushion above it.
pub const MIN_M_BITS: u32 = 64;

/// Exclusive upper bound on `m`. Section 8.2 says `[64, 2^32)`; we
/// keep it strict so a `u32` `m` value can always be safely cast to
/// `usize` on 32-bit targets without overflow.
pub const MAX_M_BITS: u64 = 1u64 << 32;

/// Inclusive bounds on `k` (the hash count), per §8.2.
pub const MIN_K: u32 = 1;
pub const MAX_K: u32 = 32;

/// Reasons a [`BloomFilter::new_empty`] call can fail. Surfaced as
/// `filter_param_out_of_range` on the wire (§8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamError {
    /// `m` is outside `[MIN_M_BITS, MAX_M_BITS)` or is not a multiple
    /// of 64.
    BadM,
    /// `k` is outside `[MIN_K, MAX_K]`.
    BadK,
}

/// Reasons an [`BloomFilter::or_mask`] apply can fail. Surfaced as
/// `or_mask_length_mismatch` on the wire (§8.4 400 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyMaskError {
    /// Supplied mask length in bytes does not equal `m / 8`.
    LengthMismatch,
}

/// A `prismoire-bloom-v1` filter held in memory.
///
/// Construction goes through [`Self::new_empty`] (apply
/// [`Self::insert`] for each key) for outbound senders, or through
/// [`Self::from_parts`] for receivers reconstructing a filter from
/// validated wire bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct BloomFilter {
    /// Hash count per §8.2; in `[MIN_K, MAX_K]`.
    pub k: u32,
    /// Bit count per §8.2; in `[MIN_M_BITS, MAX_M_BITS)` and a
    /// multiple of 64.
    pub m: u32,
    /// Sender-estimated key cardinality. Informational on the wire
    /// (§8.3); receivers use it for sizing dashboards, not routing.
    pub n_est: u64,
    /// Sender-designed false-positive rate target. Informational on
    /// the wire (§8.3); receivers use it for sizing dashboards.
    pub fpr_target: f32,
    /// Exactly `m / 8` bytes. MSB-first bit order within each byte
    /// per §8.2.
    pub bits: Vec<u8>,
}

impl BloomFilter {
    /// Build an empty filter with the given parameters. Returns
    /// [`ParamError`] if `k` or `m` is out of range.
    ///
    /// Use this on the producer side: allocate empty, then call
    /// [`Self::insert`] for each key in the closure.
    pub fn new_empty(k: u32, m: u32, n_est: u64, fpr_target: f32) -> Result<Self, ParamError> {
        if !(MIN_K..=MAX_K).contains(&k) {
            return Err(ParamError::BadK);
        }
        if m < MIN_M_BITS || (m as u64) >= MAX_M_BITS || !m.is_multiple_of(64) {
            return Err(ParamError::BadM);
        }
        Ok(Self {
            k,
            m,
            n_est,
            fpr_target,
            bits: vec![0u8; (m / 8) as usize],
        })
    }

    /// Reconstruct a filter from validated wire parts.
    ///
    /// Returns [`ParamError`] if `k` or `m` is out of range, and
    /// silently fails-as-an-error (`BadM`) if `bytes.len() != m / 8`
    /// — the wire-decode path is expected to surface the more
    /// specific `bytes_length_mismatch` error before getting here,
    /// but the guard keeps this constructor self-consistent.
    pub fn from_parts(
        k: u32,
        m: u32,
        n_est: u64,
        fpr_target: f32,
        bytes: Vec<u8>,
    ) -> Result<Self, ParamError> {
        if !(MIN_K..=MAX_K).contains(&k) {
            return Err(ParamError::BadK);
        }
        if m < MIN_M_BITS || (m as u64) >= MAX_M_BITS || !m.is_multiple_of(64) {
            return Err(ParamError::BadM);
        }
        if bytes.len() != (m / 8) as usize {
            return Err(ParamError::BadM);
        }
        Ok(Self {
            k,
            m,
            n_est,
            fpr_target,
            bits: bytes,
        })
    }

    /// Maximally-permissive sentinel filter (§8.8). Encoded as
    /// `m = 64, k = 1, bytes = 0xFF * 8`; matches every key on
    /// lookup. Used by instances whose unbounded 3-hop closure
    /// exceeds the §8.3 `MAX_ANNOUNCE_BODY` cap, or as a deliberate
    /// "advertise everything" posture.
    pub fn all_ones_sentinel() -> Self {
        Self {
            k: 1,
            m: 64,
            n_est: 0,
            fpr_target: 1.0,
            bits: vec![0xFFu8; 8],
        }
    }

    /// Compute the pair `(h_a(key), h_b(key))` per §8.2. Exposed
    /// `pub(crate)` so frontier-side helpers can amortise the two
    /// SipHash evaluations when probing the same key against
    /// multiple filters.
    pub(crate) fn hashes(key: &[u8]) -> (u64, u64) {
        // Two independent SipHasher24 instances, keyed per §8.2.
        // SipHasher24 is a streaming hasher; we feed the whole key
        // in one shot. `write` followed by `finish` matches the
        // standard SipHash-2-4 API exactly — no length prefixing,
        // no padding gymnastics on top of what siphasher does
        // internally.
        let mut ha = SipHasher24::new_with_keys(K_A.0, K_A.1);
        ha.write(key);
        let mut hb = SipHasher24::new_with_keys(K_B.0, K_B.1);
        hb.write(key);
        (ha.finish(), hb.finish())
    }

    /// Compute the `k` bit positions §8.2 prescribes for `key`.
    /// Returned positions are already taken `mod m`, so they index
    /// directly into `bits` via the MSB-first convention below.
    ///
    /// Takes `k` and `m` by value rather than `&self` so the
    /// caller (notably [`Self::insert`]) can hold a mutable borrow
    /// on `self.bits` simultaneously without fighting the borrow
    /// checker. `k` is small (≤ 32) so the iterator allocation cost
    /// is bounded; in profile we may inline this entirely.
    fn bit_positions(k: u32, m: u32, key: &[u8]) -> impl Iterator<Item = u64> {
        let (a, b) = Self::hashes(key);
        let m = m as u64;
        // Kirsch–Mitzenmacher: bit_i = (a + i*b) mod m, i ∈ [0, k).
        // u64 wrap on the intermediate (a + i*b) before the final
        // `% m` matches every other implementation we've checked.
        (0..k as u64).map(move |i| a.wrapping_add(i.wrapping_mul(b)) % m)
    }

    /// Set the `k` bits for `key`. Idempotent: re-inserting the
    /// same key is a no-op on the filter's contents.
    pub fn insert(&mut self, key: &[u8]) {
        for p in Self::bit_positions(self.k, self.m, key) {
            let (byte, mask) = byte_and_mask(p);
            self.bits[byte] |= mask;
        }
    }

    /// Membership test. Returns `true` if every one of the `k` bits
    /// for `key` is set. False positives are possible per the
    /// standard Bloom-filter guarantee; false negatives are not.
    pub fn contains(&self, key: &[u8]) -> bool {
        Self::bit_positions(self.k, self.m, key).all(|p| {
            let (byte, mask) = byte_and_mask(p);
            self.bits[byte] & mask != 0
        })
    }

    /// Apply a `/frontier/delta` OR-mask (§8.4). On success the
    /// filter's bits are replaced with `self.bits | mask`. On length
    /// mismatch the filter is left untouched.
    pub fn or_mask(&mut self, mask: &[u8]) -> Result<(), ApplyMaskError> {
        if mask.len() != self.bits.len() {
            return Err(ApplyMaskError::LengthMismatch);
        }
        for (s, m) in self.bits.iter_mut().zip(mask.iter()) {
            *s |= *m;
        }
        Ok(())
    }

    /// §7.2 coverage scan: fraction of `keys` for which
    /// [`Self::contains`] returns `true`. Returns `1.0` for an
    /// empty input (vacuous match — the §7.2 promotion threshold
    /// reads "coverage ≥ HIGH_THRESHOLD", and an empty local-user
    /// set has nothing to under-cover, so it trivially clears any
    /// finite threshold; mode promotion in that case is moot because
    /// there's nothing to push anyway).
    pub fn coverage<K: AsRef<[u8]>>(&self, keys: &[K]) -> f64 {
        if keys.is_empty() {
            return 1.0;
        }
        let hits = keys.iter().filter(|k| self.contains(k.as_ref())).count();
        hits as f64 / keys.len() as f64
    }

    /// Bytes set in the filter — the standard estimator's input for
    /// observed FPR. Phase-4 callers don't use this directly, but
    /// the operational-hardening dashboards (§20) will.
    pub fn popcount(&self) -> u64 {
        self.bits.iter().map(|b| b.count_ones() as u64).sum()
    }
}

/// MSB-first bit indexing per §8.2:
/// `bytes[p / 8] >> (7 - (p mod 8)) & 1`. Returned mask has exactly
/// one bit set, in the position that corresponds to `p`.
#[inline]
fn byte_and_mask(p: u64) -> (usize, u8) {
    let byte = (p / 8) as usize;
    let bit_in_byte = 7 - (p % 8) as u8;
    (byte, 1u8 << bit_in_byte)
}

/// Recommended `m` for a target `(n, fpr)` rounded up to a multiple
/// of 64 and clamped into the §8.2 range. Standard Bloom sizing:
/// `m = ceil(-n * ln(fpr) / (ln 2)^2)`. Used by frontier producers
/// when sizing a fresh filter.
///
/// `n_est == 0` falls back to [`MIN_M_BITS`] — there's no meaningful
/// sizing for an empty closure and the receiver only ever probes
/// against it, so the smallest valid filter is the right answer.
pub fn recommend_m(n_est: u64, fpr_target: f32) -> u32 {
    if n_est == 0 || fpr_target <= 0.0 || fpr_target >= 1.0 {
        return MIN_M_BITS;
    }
    let n = n_est as f64;
    let p = fpr_target as f64;
    let m_raw = (-n * p.ln() / (std::f64::consts::LN_2 * std::f64::consts::LN_2)).ceil();
    // Round up to a multiple of 64.
    let mut m = m_raw.max(MIN_M_BITS as f64) as u64;
    if !m.is_multiple_of(64) {
        m += 64 - (m % 64);
    }
    // Clamp into the §8.2 range.
    let upper = MAX_M_BITS - 64; // largest valid multiple of 64
    m.min(upper) as u32
}

/// Recommended `k` for `(m, n)` rounded to the nearest integer in
/// `[MIN_K, MAX_K]`. Standard Bloom sizing: `k = (m / n) * ln 2`.
pub fn recommend_k(m: u32, n_est: u64) -> u32 {
    if n_est == 0 {
        return MIN_K;
    }
    let k_raw = (m as f64 / n_est as f64) * std::f64::consts::LN_2;
    let k = k_raw.round().max(MIN_K as f64) as u32;
    k.clamp(MIN_K, MAX_K)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity guard on the `byte_and_mask` MSB-first convention.
    /// `p = 0` should select the *most* significant bit of the
    /// first byte; `p = 7` the least significant of the same byte.
    #[test]
    fn bit_indexing_is_msb_first_per_spec() {
        assert_eq!(byte_and_mask(0), (0, 0b1000_0000));
        assert_eq!(byte_and_mask(1), (0, 0b0100_0000));
        assert_eq!(byte_and_mask(7), (0, 0b0000_0001));
        assert_eq!(byte_and_mask(8), (1, 0b1000_0000));
        assert_eq!(byte_and_mask(63), (7, 0b0000_0001));
    }

    /// Two independent SipHasher24 instances keyed with §8.2's
    /// `K_A` and `K_B` must produce different digests for any
    /// non-trivial input. This catches a regression where someone
    /// "simplifies" the code by reusing one hasher with two seeds.
    #[test]
    fn hash_a_and_hash_b_are_distinct_for_nonempty_input() {
        let (a, b) = BloomFilter::hashes(b"prismoire");
        assert_ne!(a, b, "K_A and K_B must yield different digests");
    }

    /// Per §8.2 the same key on the same family always produces the
    /// same digest pair. This is the property that makes the wire
    /// format reproducible cross-implementation.
    #[test]
    fn hashes_are_deterministic() {
        let (a1, b1) = BloomFilter::hashes(b"prismoire");
        let (a2, b2) = BloomFilter::hashes(b"prismoire");
        assert_eq!((a1, b1), (a2, b2));
    }

    /// Bit positions for a known key form an arithmetic progression
    /// mod m with common difference `h_b(x)`, starting at `h_a(x)`
    /// — that's literally §8.2's formula. The test recomputes the
    /// progression by hand and compares against `bit_positions`.
    #[test]
    fn bit_positions_follow_kirsch_mitzenmacher_formula() {
        let f = BloomFilter::new_empty(7, 1024, 100, 0.01).unwrap();
        let key = b"alice";
        let (a, b) = BloomFilter::hashes(key);
        let expected: Vec<u64> = (0..7u64)
            .map(|i| a.wrapping_add(i.wrapping_mul(b)) % f.m as u64)
            .collect();
        let got: Vec<u64> = BloomFilter::bit_positions(f.k, f.m, key).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn insert_then_contains_returns_true() {
        let mut f = BloomFilter::new_empty(7, 1024, 10, 0.01).unwrap();
        f.insert(b"alice");
        f.insert(b"bob");
        assert!(f.contains(b"alice"));
        assert!(f.contains(b"bob"));
    }

    #[test]
    fn contains_for_absent_key_is_usually_false() {
        // With m=1024 and only one insert, the FPR on a random
        // 32-byte key is bounded by k/m = 7/1024 ≈ 0.7%. Try a few
        // distinct absent keys; at least most must miss.
        let mut f = BloomFilter::new_empty(7, 1024, 10, 0.01).unwrap();
        f.insert(b"alice");
        let mut hits = 0;
        for i in 0u32..32 {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&i.to_be_bytes());
            if f.contains(&key) {
                hits += 1;
            }
        }
        assert!(hits < 8, "way too many false positives: {hits}/32");
    }

    /// Empirical FPR check against the design target. With
    /// `m = 8192` bits, `k = 7`, and `n = 800` inserted keys, the
    /// theoretical FPR is `(1 - exp(-k n / m))^k ≈ 1%`. We allow up
    /// to 4× the target before failing — the test set is small so
    /// the binomial variance is real.
    #[test]
    fn empirical_fpr_is_within_design_envelope() {
        let mut f = BloomFilter::new_empty(7, 8192, 800, 0.01).unwrap();
        for i in 0u32..800 {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&i.to_be_bytes());
            // Tag the "inserted" half-space so the probe half-space
            // below has zero true overlap.
            key[4] = 0;
            f.insert(&key);
        }
        let trials = 5_000u32;
        let mut fp = 0u32;
        for i in 0u32..trials {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&i.to_be_bytes());
            key[4] = 1;
            if f.contains(&key) {
                fp += 1;
            }
        }
        let observed = fp as f64 / trials as f64;
        assert!(
            observed < 0.04,
            "observed FPR {observed:.4} >> design target 0.01"
        );
    }

    #[test]
    fn or_mask_unions_bits() {
        let mut a = BloomFilter::new_empty(7, 128, 10, 0.01).unwrap();
        let mut b = BloomFilter::new_empty(7, 128, 10, 0.01).unwrap();
        a.insert(b"alice");
        b.insert(b"bob");
        let original_b_bits = b.bits.clone();
        a.or_mask(&original_b_bits).expect("apply mask");
        assert!(a.contains(b"alice"));
        assert!(a.contains(b"bob"));
    }

    #[test]
    fn or_mask_rejects_length_mismatch() {
        let mut a = BloomFilter::new_empty(7, 128, 10, 0.01).unwrap();
        // 128 bits = 16 bytes; mask of 8 bytes must be rejected.
        let err = a.or_mask(&[0u8; 8]).unwrap_err();
        assert_eq!(err, ApplyMaskError::LengthMismatch);
    }

    #[test]
    fn coverage_of_empty_keys_is_one() {
        let f = BloomFilter::new_empty(7, 64, 0, 0.01).unwrap();
        let empty: &[[u8; 32]] = &[];
        assert_eq!(f.coverage(empty), 1.0);
    }

    #[test]
    fn coverage_against_all_ones_sentinel_is_one() {
        let f = BloomFilter::all_ones_sentinel();
        let keys: Vec<[u8; 32]> = (0u8..16).map(|i| [i; 32]).collect();
        assert_eq!(f.coverage(&keys), 1.0);
    }

    #[test]
    fn coverage_when_filter_contains_no_keys_is_low() {
        let f = BloomFilter::new_empty(7, 2048, 100, 0.01).unwrap();
        let keys: Vec<[u8; 32]> = (0u8..64).map(|i| [i; 32]).collect();
        let cov = f.coverage(&keys);
        // With nothing inserted, almost everything misses.
        assert!(cov < 0.05, "empty filter unexpectedly covers {cov}");
    }

    #[test]
    fn all_ones_sentinel_matches_every_key() {
        let f = BloomFilter::all_ones_sentinel();
        assert_eq!(f.m, 64);
        assert_eq!(f.k, 1);
        assert_eq!(f.bits, vec![0xFFu8; 8]);
        for i in 0u8..32 {
            assert!(f.contains(&[i; 32]));
        }
    }

    #[test]
    fn new_empty_rejects_out_of_range_params() {
        assert_eq!(
            BloomFilter::new_empty(0, 64, 0, 0.01).unwrap_err(),
            ParamError::BadK
        );
        assert_eq!(
            BloomFilter::new_empty(33, 64, 0, 0.01).unwrap_err(),
            ParamError::BadK
        );
        // 32 is < MIN_M_BITS (64).
        assert_eq!(
            BloomFilter::new_empty(7, 32, 0, 0.01).unwrap_err(),
            ParamError::BadM
        );
        // Non-multiple-of-64.
        assert_eq!(
            BloomFilter::new_empty(7, 100, 0, 0.01).unwrap_err(),
            ParamError::BadM
        );
    }

    #[test]
    fn from_parts_validates_byte_length() {
        // 128 bits = 16 bytes; pass 8 to provoke BadM.
        let err = BloomFilter::from_parts(7, 128, 0, 0.01, vec![0u8; 8]).unwrap_err();
        assert_eq!(err, ParamError::BadM);
    }

    #[test]
    fn recommend_m_rounds_up_to_multiple_of_64() {
        let m = recommend_m(1000, 0.01);
        assert_eq!(m % 64, 0);
        // Theoretical optimum at 1% FPR is ~9585 bits; round-up to a
        // multiple of 64 lands at 9600.
        assert!((9000..=10_000).contains(&m), "got m = {m}");
    }

    #[test]
    fn recommend_m_handles_degenerate_inputs() {
        assert_eq!(recommend_m(0, 0.01), MIN_M_BITS);
        assert_eq!(recommend_m(1000, 0.0), MIN_M_BITS);
        assert_eq!(recommend_m(1000, 1.0), MIN_M_BITS);
    }

    #[test]
    fn recommend_k_clamps_to_range() {
        // With m far smaller than n, the formula yields k < 1; clamp.
        assert_eq!(recommend_k(64, 10_000), MIN_K);
        // Sane mid-range — k=7 is the §8.2 default sizing.
        let k = recommend_k(9600, 1000);
        assert!((5..=9).contains(&k), "got k = {k}");
    }

    /// `popcount` reports the standard bit-popcount, used by §20
    /// dashboards to estimate observed FPR.
    #[test]
    fn popcount_counts_set_bits() {
        let mut f = BloomFilter::new_empty(7, 1024, 10, 0.01).unwrap();
        assert_eq!(f.popcount(), 0);
        f.insert(b"alice");
        // 7 hashes, possibly fewer distinct bit positions if two
        // hashes collide; bounded above by k.
        assert!((1..=7).contains(&f.popcount()));
    }

    /// Layer-4 property test (first Layer-4 in the codebase): with
    /// m sized to the 1% FPR target, repeated independent trials
    /// must keep the *measured* FPR within 2× of the design target
    /// the vast majority of the time. This is the property the
    /// frontier-routing path depends on for its bandwidth bound.
    ///
    /// Tagged `#[ignore]` because it runs 50 trials × 5000 probes
    /// (~ms per trial but unwelcome on every `cargo test`); the
    /// pre-release gate flips it on explicitly.
    #[test]
    #[ignore = "expensive Layer-4 property; run with `cargo test --features test-auth -- --ignored`"]
    fn property_fpr_within_2x_target_across_trials() {
        let trials = 50;
        let n = 800u32;
        let m = recommend_m(n as u64, 0.01);
        let k = recommend_k(m, n as u64);
        let mut over_threshold = 0;
        for trial in 0u32..trials {
            let mut f = BloomFilter::new_empty(k, m, n as u64, 0.01).unwrap();
            // Inserted half-space: keys keyed on (trial, i, 0).
            for i in 0..n {
                let mut key = [0u8; 32];
                key[..4].copy_from_slice(&trial.to_be_bytes());
                key[4..8].copy_from_slice(&i.to_be_bytes());
                key[8] = 0;
                f.insert(&key);
            }
            // Probe half-space: keys keyed on (trial, i, 1) — zero
            // true overlap with the inserted set by construction.
            let probes = 5_000u32;
            let mut hits = 0;
            for i in 0..probes {
                let mut key = [0u8; 32];
                key[..4].copy_from_slice(&trial.to_be_bytes());
                key[4..8].copy_from_slice(&i.to_be_bytes());
                key[8] = 1;
                if f.contains(&key) {
                    hits += 1;
                }
            }
            let observed = hits as f64 / probes as f64;
            if observed > 0.02 {
                over_threshold += 1;
            }
        }
        // Allow a few trials to exceed 2× target on small-sample
        // variance; failure mode is "consistent breach."
        assert!(
            over_threshold < trials / 5,
            "{over_threshold}/{trials} trials exceeded 2x target FPR — sizing math is wrong"
        );
    }
}
