//! Per-peer routing primitives
//! (`docs/federation-protocol.md` §7.2, §7.4, §7.5; Phase 4 of
//! `docs/federation-impl-plan.md`).
//!
//! Two concerns live here:
//!
//! 1. **Per-pair routing mode** ([`Mode`]) — the §7.2 `filtered` /
//!    `all` flag the sender uses to decide whether to consult the
//!    peer's interest filter at all. The mode is local to the sender;
//!    peers don't negotiate it. This module owns the in-memory
//!    representation and the coverage-threshold check; Phase 6.5
//!    persists the per-direction mode on `peer_frontiers`
//!    (`inbound_mode` / `outbound_mode`) and piggybacks the wire
//!    signal on `FrontierAnnounce` / `FrontierDelta` rather than
//!    the dedicated §7.2 POST /mode protocol (see
//!    `docs/federation-impl-plan.md` Phase 6.5 deviation note).
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
/// mode(B→A) are independent values. Phase 6.5 persists the
/// per-direction modes on `peer_frontiers` (`inbound_mode`,
/// `outbound_mode`); see [`Mode::as_db_str`] / [`Mode::from_db_str`]
/// for the on-disk representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Consult the peer's interest filter on every outbound object.
    /// §7.4 routing rule applies; objects whose `key(obj)` is not in
    /// the peer's appropriate filter are not enqueued for that peer.
    Filtered,
    /// Skip the filter check entirely and unconditionally push every
    /// locally-routed object. Per §7.2 a direction is promoted to
    /// `All` once the sender's local coverage of the receiver's
    /// content filter crosses [`HIGH_THRESHOLD`].
    All,
}

impl Mode {
    /// Canonical wire / on-disk string. Matches the CHECK constraint
    /// on `peer_frontiers.inbound_mode` / `outbound_mode` and the
    /// values used by the §7.2 wire field on `FrontierAnnounce` /
    /// `FrontierDelta`.
    pub fn as_db_str(self) -> &'static str {
        match self {
            Mode::Filtered => "filtered",
            Mode::All => "all",
        }
    }

    /// Parse a value stored in `peer_frontiers.inbound_mode` /
    /// `outbound_mode` or received over the wire. Unknown strings
    /// fall back to [`Mode::Filtered`] — the §7.2 conservative
    /// default — and the caller is responsible for logging if the
    /// drop matters (a CHECK constraint blocks the DB path; only
    /// inbound wire bodies and forward-compat probes can reach this
    /// branch).
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "all" => Mode::All,
            _ => Mode::Filtered,
        }
    }
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

/// §12.2 / §12.6 forwarding fanout cap for move declarations. Replaces
/// the ordinary [`REDUNDANCY_K`] when the object being forwarded is a
/// §5.1 `move` — the unconditional-flood property of §12 widens the
/// per-object fanout from the ordinary 2 to 5 distinct downstream
/// peers. Combined with the [`ForwardingClass::Move`] bypass of the
/// §7.4 interest-filter dispatch, every active peer that has not yet
/// received the move (modulo the dedup-LRU bitset) is a candidate.
pub const REDUNDANCY_K_MOVE: usize = 5;

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
    /// §5.1 `move` declaration. §12 propagation override: every
    /// active peer receives every move regardless of `mode(self → P)`
    /// or any interest-filter membership, and the per-object fanout
    /// cap is [`REDUNDANCY_K_MOVE`] (5) instead of [`REDUNDANCY_K`]
    /// (2). The routing key is the moving identity K (the same field
    /// the user's other signed objects key on for the §7.4 dispatch
    /// table), but the filter check is bypassed entirely.
    Move,
}

impl ForwardingClass {
    /// Pick the receiver-side filter to consult per the §7.4
    /// dispatch table. `Move` bypasses every filter under the §12
    /// unconditional-flood override; callers must check
    /// [`Self::bypasses_filters`] before reaching this method, or
    /// the bloom path below would erroneously gate move propagation
    /// on the per-peer interest filters.
    fn select_filter<'a>(&self, cf: &'a BloomFilter, ef: &'a BloomFilter) -> &'a BloomFilter {
        match self {
            ForwardingClass::TrustEdge => ef,
            ForwardingClass::Authored => cf,
            // `Move` is documented to bypass §7.4 filter dispatch via
            // [`Self::bypasses_filters`]; reaching this arm means a
            // caller went through the bloom-membership path for a
            // Move object, which is a programmer error (§12 mandates
            // unconditional flood). Falling through to a filter would
            // silently under-shoot the spec — neither an under-shoot
            // nor an over-shoot is a defensible default for a control-
            // plane class, so panic loudly.
            ForwardingClass::Move => {
                unreachable!(
                    "select_filter called on ForwardingClass::Move; \
                     callers must short-circuit on `bypasses_filters` first"
                )
            }
        }
    }

    /// True iff §7.4's interest-filter dispatch is bypassed for this
    /// class. Today: only [`Self::Move`] (the §12 unconditional-flood
    /// override). Used by [`peers_interested_in`] to short-circuit
    /// the bloom check entirely and return every active peer.
    pub fn bypasses_filters(self) -> bool {
        matches!(self, ForwardingClass::Move)
    }

    /// Per-class §7.5 fanout cap. Ordinary classes use
    /// [`REDUNDANCY_K`] (= 2); moves use [`REDUNDANCY_K_MOVE`] (= 5)
    /// per §12.2 / §12.6.
    pub fn redundancy_cap(self) -> usize {
        match self {
            ForwardingClass::Move => REDUNDANCY_K_MOVE,
            _ => REDUNDANCY_K,
        }
    }
}

/// One candidate peer to deliver an object to.
///
/// The forwarder loop consumes this to mint the outbound envelope and
/// update the dedup-LRU `forwarded_to` bitset. Carries the peer's
/// instance pubkey (the on-the-wire identity used by
/// `FederationTransport::request`) and the persisted `outbound_mode`
/// the sender uses for that direction. The mode is *load-bearing* in
/// [`peers_interested_in`]: candidates with [`Mode::All`] reach this
/// struct without a bloom-membership check (§7.2 short-circuit);
/// candidates with [`Mode::Filtered`] only reach it after `key(obj)`
/// passed the per-class filter test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRouting {
    /// The peer's instance signing key — the `PeerId` the federation
    /// transport routes against and the recipient of the outbound
    /// envelope.
    pub instance_pubkey: [u8; 32],
    /// Direction-mode the sender currently uses for `self → peer`
    /// (read from `peer_frontiers.outbound_mode`). When `All` the
    /// candidate is included regardless of bloom membership; when
    /// `Filtered` the candidate was admitted by the `key(obj)`
    /// membership check.
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
/// When the persisted `peer_frontiers.outbound_mode` is `all` for a
/// peer (i.e. the §7.2 detection rule has promoted this direction),
/// the bloom-membership check is short-circuited and the peer is
/// included unconditionally. The hysteresis band (`Mode::All` holds
/// down to [`LOW_THRESHOLD`] = 0.60) means an `All`-mode peer may
/// briefly receive objects whose `key(obj)` would have missed a
/// fresh filter probe; that over-delivery is the deliberate §7.2
/// trade-off (skip the per-object hash work in the common case where
/// almost everything would pass anyway, accept some extra fanout
/// while coverage decays toward [`LOW_THRESHOLD`] before the row
/// flips back). The conservative `Filtered` default applies if the
/// frontier row was inserted before Phase 6.5 or if detection has
/// never crossed [`HIGH_THRESHOLD`].
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
                f.ef_bytes AS \"ef_bytes?: Vec<u8>\", \
                f.outbound_mode AS \"outbound_mode?: String\" \
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

        // §12 unconditional-flood override: classes that
        // `bypasses_filters` (today: only `Move`) reach every active
        // peer regardless of whether a `peer_frontiers` row exists,
        // what `outbound_mode` is recorded, or whether `key` would
        // have hit the bloom. The dedup-LRU + `REDUNDANCY_K_MOVE`
        // budget still bound actual fanout downstream.
        if class.bypasses_filters() {
            let outbound_mode = row
                .outbound_mode
                .as_deref()
                .map(Mode::from_db_str)
                .unwrap_or(Mode::Filtered);
            out.push(PeerRouting {
                instance_pubkey: pubkey,
                mode: outbound_mode,
            });
            continue;
        }

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
        let outbound_mode = row
            .outbound_mode
            .as_deref()
            .map(Mode::from_db_str)
            .unwrap_or(Mode::Filtered);
        // §7.2: All-mode skips the bloom check for this direction.
        // Filtered falls back to the per-class membership test.
        let admitted = match outbound_mode {
            Mode::All => true,
            Mode::Filtered => {
                let filter = class.select_filter(&cf, &ef);
                filter.contains(key)
            }
        };
        if admitted {
            out.push(PeerRouting {
                instance_pubkey: pubkey,
                mode: outbound_mode,
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
/// local user pubkeys. Returns the mode this sender should now use
/// for the `sender → peer` direction, applied by the receiver-side
/// handlers in `handle_frontier_announce` / `handle_frontier_delta`
/// and persisted on `peer_frontiers.outbound_mode` (Phase 6.5).
///
/// `current_mode` exists so the hysteresis check is correct: a pair
/// in `Filtered` mode crosses to `All` only when coverage ≥
/// [`HIGH_THRESHOLD`], and once in `All` mode drops back to
/// `Filtered` only when coverage < [`LOW_THRESHOLD`]. Without the
/// hysteresis branch a pair sitting at exactly 0.79 would oscillate
/// modes every frontier refresh.
///
/// **Empty-local-users guard.** [`BloomFilter::coverage`] returns
/// `1.0` over an empty key set (vacuously: all zero of the zero
/// supplied keys hit). Without an early return that would promote
/// every peer of a fresh-bootstrap instance to `All` on their first
/// announce, violating §7.2's "fresh peering never starts in
/// all-mode." When `local_user_keys` is empty we preserve
/// `current_mode` so the conservative `Filtered` default that
/// every row starts in stays untouched until there's actually a
/// coverage measurement to act on.
pub fn classify_mode(
    current_mode: Mode,
    peer_content_filter: &BloomFilter,
    local_user_keys: &[[u8; 32]],
) -> Mode {
    if local_user_keys.is_empty() {
        return current_mode;
    }
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
    fn classify_empty_local_users_preserves_current_mode() {
        // Regression for the bootstrap pitfall: BloomFilter::coverage
        // returns 1.0 over an empty key set, which would spuriously
        // promote every fresh-instance peer to All on first announce.
        // Guard returns `current_mode` so the conservative `Filtered`
        // default a fresh row carries is preserved.
        let f = BloomFilter::new_empty(7, 1024, 0, 0.01).unwrap();
        assert_eq!(
            classify_mode(Mode::Filtered, &f, &[]),
            Mode::Filtered,
            "empty local-user set on a Filtered pair must NOT promote to All"
        );
        // Symmetry: an `All`-mode pair with empty local users also
        // holds (don't demote on no signal either; wait for a real
        // coverage measurement).
        assert_eq!(
            classify_mode(Mode::All, &f, &[]),
            Mode::All,
            "empty local-user set on an All pair must NOT demote"
        );
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
