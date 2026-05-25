//! Per-peer routing primitives
//! (`docs/federation-protocol.md` §7.2, §7.4, §7.5; Phase 4 of
//! `docs/federation-impl-plan.md`).
//!
//! Two concerns live here:
//!
//! 1. **Per-pair routing mode** ([`Mode`]) — the §7.2 `filtered` /
//!    `all` flag the sender uses to decide whether to consult the
//!    peer's interest filter at all. The mode is local to the sender;
//!    peers don't negotiate it. Today this module owns the in-memory
//!    representation and the coverage-threshold check; the on-the-wire
//!    `mode-promote` / `mode-demote` protocol (§7.2 mode-change
//!    messages) is Phase 5+ work.
//!
//! 2. **Interest-filter dispatch** ([`ForwardingClass`],
//!    [`peers_interested_in`]) — the §7.4 routing rule that maps a
//!    signed object class plus its routing key to the receiver's
//!    appropriate filter (`content_filter` for everything except
//!    trust-edges, `edge_origin_filter` for trust-edges) and yields
//!    the subset of active peers that should receive a push.
//!
//! Outbound delivery itself (queueing, retry, dedup-LRU bookkeeping,
//! REDUNDANCY_K accounting) is a later phase; this module only
//! decides *who* the candidates are. The forwarder loop in §7.5 will
//! call into [`peers_interested_in`] for each object and then apply
//! the dedup-LRU + `REDUNDANCY_K` cap on top.
//!
//! The bloom-filter primitive lives in [`super::bloom`] and the
//! `peer_frontiers` row layout lives in
//! [`super::frontier`].

use std::sync::Arc;

use crate::AppState;
use crate::federation::bloom::BloomFilter;

/// §7.2 per-pair routing mode for a single direction (sender → peer).
///
/// The mode is *sender-local*: A's view of mode(A→B) and B's view of
/// mode(B→A) are independent values. Today we don't persist this —
/// every direction starts in [`Mode::Filtered`] per §7.2 "fresh
/// peering never starts in all-mode" and the mode-change wire protocol
/// (§7.2 mode-promote / mode-demote) is not yet implemented. Once
/// Phase 5+ ships the wire surface this enum becomes the value stored
/// in a `peer_routing_mode` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Consult the peer's interest filter on every outbound object.
    /// §7.4 routing rule applies; objects whose `key(obj)` is not in
    /// the peer's appropriate filter are not enqueued for that peer.
    Filtered,
    /// Skip the filter check entirely and unconditionally push every
    /// locally-routed object. Reserved for high-overlap pairs that
    /// crossed [`HIGH_THRESHOLD`]; today no pair ever enters this
    /// mode because the wire protocol that flips it is Phase 5+.
    All,
}

/// §7.5 per-object forwarding fanout cap. An object is forwarded to
/// at most `REDUNDANCY_K` distinct downstream peers; the originator's
/// initial push counts against the same budget. The default value
/// here matches `docs/federation-protocol.md` §7.5 "REDUNDANCY_K
/// default — RESOLVED at K=2".
///
/// Exposed as a `pub const` so the dedup-LRU bookkeeping in the
/// forwarder loop (Phase 5+) and the integration tests can reference
/// a single source of truth. The spec calls this an instance-tunable
/// knob (§7.5 "Gossip parameters are local policy"); the constant
/// here is the build-time default. A future Phase will make it a
/// runtime `instance_config` value if operators need to override it.
pub const REDUNDANCY_K: usize = 2;

/// §7.2 mode-promote threshold (default 80%). When the sender's local
/// coverage scan against the peer's `content_filter` reaches or
/// exceeds this value, the sender promotes the direction to [`Mode::All`]
/// (subject to the mode-change wire handshake, Phase 5+). Expressed
/// as a fraction so it composes directly with [`BloomFilter::coverage`].
pub const HIGH_THRESHOLD: f64 = 0.80;

/// §7.2 mode-demote threshold (default 60%). When the sender's local
/// coverage drops below this value, the sender demotes the direction
/// back to [`Mode::Filtered`]. The 20-point gap below
/// [`HIGH_THRESHOLD`] is hysteresis against filter drift; without
/// it a pair sitting at exactly 80% coverage would flap modes every
/// frontier refresh.
pub const LOW_THRESHOLD: f64 = 0.60;

/// §7.4 forwarding-class discriminator for routing dispatch.
///
/// The class determines two things:
///
/// 1. Which of the receiver's two filters to consult — trust-edges
///    look up against `edge_origin_filter`; everything else looks up
///    against `content_filter`.
/// 2. What the routing *key* is for an object — for most classes the
///    key is the author's public key; for trust-edges it is the
///    signer (== source) of the edge; for attests / user-status it is
///    the subject; for admin-rm it is the target post's author. The
///    caller resolves the key from the object before calling
///    [`peers_interested_in`].
///
/// The §7.4 table also lists `reports`, `user-status`, and
/// `thread-status` as "do not gossip" — they reach peers via
/// different paths (§16.2, §17.2, §18.2) and never feed this routing
/// dispatch. Those classes are deliberately absent from this enum so
/// a caller that adds them by accident gets a type error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardingClass {
    /// Trust-edge signature → routes against the receiver's
    /// `edge_origin_filter` (§7.4); key is `signer(edge)`.
    TrustEdge,
    /// Every author-keyed class — post-rev, retract, profile,
    /// thread-create, deactivate, attest (key = subject), admin-rm
    /// (key = target_author), thread-status (key = thread OP author).
    /// Routes against the receiver's `content_filter` (§7.4).
    Authored,
}

impl ForwardingClass {
    /// Pick the receiver-side filter to consult per the §7.4
    /// dispatch table.
    fn select_filter<'a>(&self, cf: &'a BloomFilter, ef: &'a BloomFilter) -> &'a BloomFilter {
        match self {
            ForwardingClass::TrustEdge => ef,
            ForwardingClass::Authored => cf,
        }
    }
}

/// One candidate peer to deliver an object to.
///
/// The forwarder loop (Phase 5+) consumes this to mint the outbound
/// envelope and update the dedup-LRU `forwarded_to` bitset. Carries
/// the peer's instance pubkey (the on-the-wire identity used by
/// `FederationTransport::request`) and the mode the sender currently
/// uses for that direction — the mode is informational here; the
/// filter check has already been resolved by [`peers_interested_in`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRouting {
    /// The peer's instance signing key — the `PeerId` the federation
    /// transport routes against and the recipient of the outbound
    /// envelope.
    pub instance_pubkey: [u8; 32],
    /// Direction-mode the sender currently uses for `self → peer`.
    /// Always [`Mode::Filtered`] today; reserved for the Phase 5+
    /// promote wire flow.
    pub mode: Mode,
}

/// Enumerate the active peers that are interested in `key` for an
/// object of class `class`, per §7.4.
///
/// Walks `peers WHERE status = 'active'` joined with `peer_frontiers`,
/// and for each row picks the receiver-side filter from the §7.4
/// table (content vs edge-origin), reconstructs the [`BloomFilter`]
/// from the persisted parameters + bytes, and checks membership for
/// `key`. A peer with no `peer_frontiers` row yet (we have never
/// received their frontier) is treated as "filtered, empty
/// frontier" — they receive nothing until their first announce per
/// §7.2 "filtered mode with empty interest filters".
///
/// A peer whose stored filter parameters are out of spec range (a
/// row written before this server's validation tightened) is skipped
/// with a warn-level log rather than crashing the whole fanout;
/// `from_parts` is the canonical validator and its rejection means
/// the row is unusable for routing regardless.
///
/// Every returned [`PeerRouting`] currently carries
/// [`Mode::Filtered`]. The `peer_frontiers` row does not yet store
/// the per-direction mode and the §7.2 promote/demote wire signal is
/// reserved for Phase 5+; until then this function does not surface
/// `All`-mode peers even if they would short-circuit the filter
/// check. That is conservative — a missed `All`-mode peer falls back
/// to the pull-backfill path, which is correctness-preserving by
/// construction (false negatives in routing are allowed; false
/// positives only waste bandwidth).
pub async fn peers_interested_in(
    state: &Arc<AppState>,
    class: ForwardingClass,
    key: &[u8],
) -> Result<Vec<PeerRouting>, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT p.instance_pubkey AS \"instance_pubkey!: Vec<u8>\", \
                f.cf_k AS \"cf_k?: i64\", f.cf_m AS \"cf_m?: i64\", \
                f.cf_n_est AS \"cf_n_est?: i64\", \
                f.cf_fpr_target AS \"cf_fpr_target?: f64\", \
                f.cf_bytes AS \"cf_bytes?: Vec<u8>\", \
                f.ef_k AS \"ef_k?: i64\", f.ef_m AS \"ef_m?: i64\", \
                f.ef_n_est AS \"ef_n_est?: i64\", \
                f.ef_fpr_target AS \"ef_fpr_target?: f64\", \
                f.ef_bytes AS \"ef_bytes?: Vec<u8>\" \
         FROM peers p \
         LEFT JOIN peer_frontiers f ON f.peer_pubkey = p.instance_pubkey \
         WHERE p.status = 'active'",
    )
    .fetch_all(&state.db)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let Ok(pubkey) = <[u8; 32]>::try_from(row.instance_pubkey.as_slice()) else {
            // A peers row whose pubkey is not 32 bytes shouldn't exist
            // (the CHECK constraint blocks it). Skip defensively.
            tracing::warn!("peers row with non-32-byte instance_pubkey skipped");
            continue;
        };
        // No frontier row yet → treat as Filtered + empty filter:
        // miss every key. The peer joins the routing population only
        // after their first §8.3 announce.
        let Some(cf) = build_filter(
            row.cf_k,
            row.cf_m,
            row.cf_n_est,
            row.cf_fpr_target,
            row.cf_bytes,
        ) else {
            continue;
        };
        let Some(ef) = build_filter(
            row.ef_k,
            row.ef_m,
            row.ef_n_est,
            row.ef_fpr_target,
            row.ef_bytes,
        ) else {
            continue;
        };
        let filter = class.select_filter(&cf, &ef);
        if filter.contains(key) {
            out.push(PeerRouting {
                instance_pubkey: pubkey,
                mode: Mode::Filtered,
            });
        }
    }
    Ok(out)
}

/// Reconstruct a single bloom filter from one half of a
/// `peer_frontiers` row. Returns `None` if any column is NULL (no
/// frontier announced yet) or if the parameters fail
/// [`BloomFilter::from_parts`] validation.
fn build_filter(
    k: Option<i64>,
    m: Option<i64>,
    n_est: Option<i64>,
    fpr_target: Option<f64>,
    bytes: Option<Vec<u8>>,
) -> Option<BloomFilter> {
    let k = k?;
    let m = m?;
    let n_est = n_est?;
    let fpr_target = fpr_target?;
    let bytes = bytes?;
    // Narrow the i64 column types back to the bloom API's u32 / u64.
    // A negative value would be a CHECK-constraint violation; treat
    // it the same as out-of-range and skip the peer.
    let k_u = u32::try_from(k).ok()?;
    let m_u = u32::try_from(m).ok()?;
    let n_u = u64::try_from(n_est).ok()?;
    match BloomFilter::from_parts(k_u, m_u, n_u, fpr_target as f32, bytes) {
        Ok(f) => Some(f),
        Err(e) => {
            tracing::warn!(
                error = ?e,
                "peer_frontiers row failed bloom validation; skipping"
            );
            None
        }
    }
}

/// §7.2 mode classification given a peer's `content_filter` and the
/// local user pubkeys. Returns the mode this sender *would* use for
/// this direction if it were ready to apply the §7.2 wire protocol.
/// Today the result is purely informational (no caller flips a
/// persisted mode based on it); Phase 5+ wires it into the
/// mode-promote / mode-demote handshake.
///
/// `current_mode` exists so the hysteresis check is correct: a pair
/// in `Filtered` mode crosses to `All` only when coverage ≥
/// [`HIGH_THRESHOLD`], and once in `All` mode drops back to
/// `Filtered` only when coverage < [`LOW_THRESHOLD`]. Without the
/// hysteresis branch a pair sitting at exactly 0.79 would oscillate
/// modes every frontier refresh.
pub fn classify_mode(
    current_mode: Mode,
    peer_content_filter: &BloomFilter,
    local_user_keys: &[[u8; 32]],
) -> Mode {
    let coverage = peer_content_filter.coverage(local_user_keys);
    match current_mode {
        Mode::Filtered if coverage >= HIGH_THRESHOLD => Mode::All,
        Mode::All if coverage < LOW_THRESHOLD => Mode::Filtered,
        _ => current_mode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_key_filter(keys: &[&[u8]]) -> BloomFilter {
        let mut f = BloomFilter::new_empty(7, 1024, keys.len() as u64, 0.01).unwrap();
        for k in keys {
            f.insert(k);
        }
        f
    }

    #[test]
    fn classify_promotes_on_high_coverage() {
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        let mut f = BloomFilter::new_empty(7, 1024, 2, 0.01).unwrap();
        f.insert(&alice);
        f.insert(&bob);
        // 100% coverage → promote.
        assert_eq!(classify_mode(Mode::Filtered, &f, &[alice, bob]), Mode::All);
    }

    #[test]
    fn classify_holds_at_filtered_in_hysteresis_band() {
        // Build a filter that covers ~50% of the local key set
        // (clearly < HIGH_THRESHOLD).
        let mut keys = Vec::new();
        for i in 0..10u8 {
            keys.push([i; 32]);
        }
        let mut f = BloomFilter::new_empty(7, 1024, 5, 0.01).unwrap();
        for k in &keys[..5] {
            f.insert(k);
        }
        assert_eq!(
            classify_mode(Mode::Filtered, &f, &keys),
            Mode::Filtered,
            "below HIGH_THRESHOLD must stay in Filtered"
        );
    }

    #[test]
    fn classify_demotes_below_low_threshold() {
        // All-mode pair whose coverage has decayed to 0%.
        let empty = BloomFilter::new_empty(7, 1024, 0, 0.01).unwrap();
        let alice = [1u8; 32];
        assert_eq!(classify_mode(Mode::All, &empty, &[alice]), Mode::Filtered);
    }

    #[test]
    fn classify_all_mode_holds_in_hysteresis_band() {
        // Coverage in [LOW_THRESHOLD, HIGH_THRESHOLD) keeps All-mode.
        // Build a filter that hits exactly 7 of 10 keys (70%).
        let mut keys = Vec::new();
        for i in 0..10u8 {
            keys.push([i; 32]);
        }
        let mut f = BloomFilter::new_empty(7, 1024, 7, 0.01).unwrap();
        for k in &keys[..7] {
            f.insert(k);
        }
        assert_eq!(classify_mode(Mode::All, &f, &keys), Mode::All);
    }

    #[test]
    fn forwarding_class_dispatch() {
        // content_filter contains "alice"; edge_origin_filter
        // contains "bob". A trust-edge keyed on "alice" must NOT
        // match (wrong filter); a post-rev keyed on "alice" must
        // match.
        let cf = one_key_filter(&[b"alice"]);
        let ef = one_key_filter(&[b"bob"]);
        assert!(
            ForwardingClass::Authored
                .select_filter(&cf, &ef)
                .contains(b"alice")
        );
        assert!(
            !ForwardingClass::TrustEdge
                .select_filter(&cf, &ef)
                .contains(b"alice")
        );
        assert!(
            ForwardingClass::TrustEdge
                .select_filter(&cf, &ef)
                .contains(b"bob")
        );
    }

    #[test]
    fn redundancy_k_is_two() {
        // Pin the §7.5 resolved default. If this changes intentionally,
        // update the const and this test together.
        assert_eq!(REDUNDANCY_K, 2);
    }

    #[test]
    fn build_filter_round_trip() {
        let f = build_filter(
            Some(7),
            Some(1024),
            Some(0),
            Some(0.01),
            Some(vec![0u8; 128]),
        );
        assert!(f.is_some());
    }

    #[test]
    fn build_filter_null_returns_none() {
        assert!(build_filter(None, None, None, None, None).is_none());
    }
}
