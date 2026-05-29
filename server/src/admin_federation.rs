//! Admin Federation tab handlers.
//!
//! Operator-facing surface over the §5.4 peering handshake. Every
//! route is admin-gated and mounted under `/api/admin/federation`:
//!
//! - `GET    /peers` — this-instance identity + every peer row.
//! - `POST   /preview` — unauthenticated `GET /federation/v1/identity`
//!   probe against an operator-typed domain, so the UI can show who
//!   they're about to peer with *before* any handshake traffic.
//! - `POST   /peers` — initiate an outbound peer-request (§5.4 step 1).
//! - `POST   /peers/{pubkey_hex}/accept` — accept a pending inbound
//!   request (§5.4 step 2, operator side).
//! - `DELETE /peers/{pubkey_hex}` — defederate: §5.4 wire DELETE for an
//!   `active` relationship, or a local row cleanup for a pending /
//!   rejected / terminated row that never reached `active`.
//!
//! The two-stage federate flow (preview → initiate) keeps the operator
//! in the loop on the §5.2 domain↔pubkey binding: `preview` returns the
//! pubkey the remote instance claims, and `initiate` takes that pubkey
//! back as an explicit argument, so a MITM swapping the identity card
//! can't silently bind a different key than the one the operator saw.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::admin::require_admin;
use crate::error::{AppError, ErrorCode};
use crate::federation::domain::parse_instance_domain;
use crate::federation::identity::IdentityCard;
use crate::federation::peering::{
    InitiateError, TerminationReason, decode_text_array, operator_accept_peer_request,
    operator_initiate_peer_request, operator_terminate_peer_relationship,
};
use crate::session::AuthUser;
use crate::state::AppState;
use crate::users::hex_lower;

// ---------------------------------------------------------------------------
// InitiateError -> AppError
// ---------------------------------------------------------------------------

impl From<InitiateError> for AppError {
    fn from(e: InitiateError) -> Self {
        match e {
            // Transport couldn't deliver — DNS, connect, TLS, timeout.
            InitiateError::Transport(_) => AppError::code(ErrorCode::PeerUnreachable),
            // Reached the peer but it refused the handshake payload.
            InitiateError::UnexpectedStatus(_) => AppError::code(ErrorCode::PeerHandshakeFailed),
            // Local DB failure — opaque 500.
            InitiateError::Db(_) => AppError::code(ErrorCode::Internal),
            InitiateError::SelfPeering => AppError::code(ErrorCode::SelfPeering),
            InitiateError::DomainConflict => AppError::code(ErrorCode::PeerDomainConflict),
            InitiateError::InvalidTargetDomain => AppError::code(ErrorCode::InvalidPeerDomain),
        }
    }
}

// ---------------------------------------------------------------------------
// Response / request types
// ---------------------------------------------------------------------------

/// This-instance identity, surfaced so the operator can read off their
/// own domain + fingerprint (to share out-of-band with a peer admin).
#[derive(Serialize)]
pub struct InstanceIdentity {
    pub domain: String,
    pub pubkey_hex: String,
}

/// One row of the `peers` table, flattened for the dashboard table.
#[derive(Serialize)]
pub struct PeerView {
    pub pubkey_hex: String,
    pub domain: String,
    pub status: String,
    pub direction: String,
    /// Capabilities proposed at handshake time.
    pub capabilities: Vec<String>,
    /// Capabilities both sides agreed on (empty until `active`).
    pub agreed_capabilities: Vec<String>,
    pub decision_message: Option<String>,
    pub termination_reason: Option<String>,
    pub first_seen: String,
    pub last_handshake: Option<String>,
}

/// `GET /api/admin/federation/peers` response.
#[derive(Serialize)]
pub struct PeersListResponse {
    pub instance: InstanceIdentity,
    pub peers: Vec<PeerView>,
}

/// `POST /api/admin/federation/preview` request.
#[derive(Deserialize)]
pub struct PreviewRequest {
    pub domain: String,
}

/// `POST /api/admin/federation/preview` response — the remote
/// instance's self-reported identity card plus two locally-computed
/// hints (`is_self`, `existing_status`) the UI needs to decide whether
/// "federate" is even a sensible next step.
#[derive(Serialize)]
pub struct PreviewResponse {
    pub domain: String,
    pub pubkey_hex: String,
    pub protocol_versions: Vec<u64>,
    pub capabilities: Vec<String>,
    pub announce: Option<String>,
    pub instance_age_days: Option<u64>,
    pub user_count_bucket: Option<String>,
    /// True when the probed instance is *this* instance.
    pub is_self: bool,
    /// Status of an existing `peers` row for this pubkey, if any.
    pub existing_status: Option<String>,
}

/// `POST /api/admin/federation/peers` request.
#[derive(Deserialize)]
pub struct InitiateRequest {
    pub domain: String,
    /// The pubkey the operator confirmed from `preview` — bound
    /// explicitly so a swapped identity card can't redirect the
    /// handshake to a different key than the one they saw.
    pub pubkey_hex: String,
    pub capabilities: Vec<String>,
    pub introduction: Option<String>,
}

/// `POST /api/admin/federation/peers` response.
#[derive(Serialize)]
pub struct InitiateResponse {
    pub request_id: String,
}

/// `DELETE /api/admin/federation/peers/{pubkey_hex}` response.
#[derive(Serialize)]
pub struct DefederateResponse {
    /// `"terminated"` when a §5.4 wire DELETE went out (was `active`),
    /// `"removed"` when only a local row was dropped.
    pub action: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode a 64-char lowercase-hex string into a 32-byte pubkey.
/// Returns `InvalidPeerDomain`-flavoured `PeerNotFound` on any
/// malformed input — the caller's path parameter is operator-typed.
fn parse_pubkey_hex(s: &str) -> Result<[u8; 32], AppError> {
    if s.len() != 64 {
        return Err(AppError::code(ErrorCode::PeerNotFound));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = u8::from_str_radix(&s[2 * i..2 * i + 1], 16)
            .map_err(|_| AppError::code(ErrorCode::PeerNotFound))?;
        let lo = u8::from_str_radix(&s[2 * i + 1..2 * i + 2], 16)
            .map_err(|_| AppError::code(ErrorCode::PeerNotFound))?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// GET /api/admin/federation/peers
// ---------------------------------------------------------------------------

/// List every peer row plus this instance's own identity.
pub async fn list_peers(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let rows = sqlx::query!(
        "SELECT instance_pubkey, instance_domain, status, direction, \
                capabilities, agreed_capabilities, decision_message, \
                termination_reason, first_seen, last_handshake \
         FROM peers ORDER BY first_seen DESC",
    )
    .fetch_all(&state.db)
    .await?;

    let peers = rows
        .into_iter()
        .map(|r| PeerView {
            pubkey_hex: hex_lower(&r.instance_pubkey),
            domain: r.instance_domain,
            status: r.status,
            direction: r.direction,
            capabilities: r
                .capabilities
                .as_deref()
                .and_then(decode_text_array)
                .unwrap_or_default(),
            agreed_capabilities: r
                .agreed_capabilities
                .as_deref()
                .and_then(decode_text_array)
                .unwrap_or_default(),
            decision_message: r.decision_message,
            termination_reason: r.termination_reason,
            first_seen: r.first_seen,
            last_handshake: r.last_handshake,
        })
        .collect();

    Ok(Json(PeersListResponse {
        instance: InstanceIdentity {
            domain: state.instance_domain.clone(),
            pubkey_hex: hex_lower(state.instance_key.public_bytes()),
        },
        peers,
    }))
}

// ---------------------------------------------------------------------------
// POST /api/admin/federation/preview
// ---------------------------------------------------------------------------

/// Probe an operator-typed domain's `/federation/v1/identity` card.
///
/// Validates the domain at this boundary (so a typo surfaces as a clean
/// `invalid_peer_domain` rather than a transport-layer failure), fetches
/// the card over the SSRF-checked unauthenticated transport, decodes it,
/// and annotates with `is_self` / `existing_status` so the UI can grey
/// out "federate" when it would be a no-op or an error.
pub async fn preview(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<PreviewRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let domain = req.domain.trim().to_string();
    if parse_instance_domain(&domain).is_err() {
        return Err(AppError::code(ErrorCode::InvalidPeerDomain));
    }

    let response = state
        .federation_transport
        .fetch_identity(&domain)
        .await
        .map_err(|_| AppError::code(ErrorCode::PeerUnreachable))?;

    if response.status() != StatusCode::OK {
        return Err(AppError::code(ErrorCode::PeerUnreachable));
    }

    let card = IdentityCard::decode(response.body())
        .ok_or_else(|| AppError::code(ErrorCode::PeerIdentityInvalid))?;

    let is_self = card.instance_pubkey == *state.instance_key.public_bytes();

    let pubkey_slice: &[u8] = &card.instance_pubkey;
    let existing = sqlx::query!(
        "SELECT status FROM peers WHERE instance_pubkey = ?",
        pubkey_slice,
    )
    .fetch_optional(&state.db)
    .await?;

    Ok(Json(PreviewResponse {
        domain: card.instance_domain,
        pubkey_hex: hex_lower(&card.instance_pubkey),
        protocol_versions: card.protocol_versions,
        capabilities: card.capabilities,
        announce: card.announce,
        instance_age_days: card.instance_age_days,
        user_count_bucket: card.user_count_bucket,
        is_self,
        existing_status: existing.map(|r| r.status),
    }))
}

// ---------------------------------------------------------------------------
// POST /api/admin/federation/peers
// ---------------------------------------------------------------------------

/// Initiate an outbound peer-request (§5.4 step 1).
pub async fn initiate_peer(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<InitiateRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let domain = req.domain.trim().to_string();
    let target_pubkey = parse_pubkey_hex(req.pubkey_hex.trim())
        .map_err(|_| AppError::code(ErrorCode::PeerIdentityInvalid))?;

    let request_id = operator_initiate_peer_request(
        &state.db,
        &state.instance_key,
        &state.instance_domain,
        &state.federation_transport,
        target_pubkey,
        &domain,
        req.capabilities,
        req.introduction,
    )
    .await?;

    Ok(Json(InitiateResponse {
        request_id: hex_lower(&request_id),
    }))
}

// ---------------------------------------------------------------------------
// POST /api/admin/federation/peers/{pubkey_hex}/accept
// ---------------------------------------------------------------------------

/// Accept a pending inbound peer-request (§5.4 step 2, operator side).
///
/// The route addresses the peer by pubkey; the §5.4 callback needs the
/// `request_id`, so we look up the `pending_inbound` row first and 404
/// (`peer_not_found`) if there's nothing to accept.
pub async fn accept_peer(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey_hex): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let pubkey = parse_pubkey_hex(&pubkey_hex)?;
    let pubkey_slice: &[u8] = &pubkey;
    let row = sqlx::query!(
        "SELECT request_id FROM peers \
         WHERE instance_pubkey = ? AND status = 'pending_inbound' LIMIT 1",
        pubkey_slice,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::PeerNotFound))?;

    let request_id: [u8; 16] = row
        .request_id
        .as_slice()
        .try_into()
        .map_err(|_| AppError::code(ErrorCode::PeerNotFound))?;

    operator_accept_peer_request(
        &state.db,
        &state.instance_key,
        &state.instance_domain,
        &state.federation_transport,
        request_id,
    )
    .await?;

    // §8.6 first-contact: now that the peer is active on our side,
    // announce our frontier so its routing leaves empty-filter mode.
    crate::federation::frontier::spawn_first_contact_announce(state.clone(), pubkey);

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// DELETE /api/admin/federation/peers/{pubkey_hex}
// ---------------------------------------------------------------------------

/// Defederate from a peer.
///
/// For an `active` relationship this sends the §5.4 wire DELETE and
/// flips the row to `terminated`. For any non-active row (pending,
/// rejected, terminated) there's no live relationship to tear down, so
/// the row is simply dropped locally — this is the "cancel a pending
/// request" / "clear a dead row" path.
pub async fn defederate(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey_hex): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let pubkey = parse_pubkey_hex(&pubkey_hex)?;
    let pubkey_slice: &[u8] = &pubkey;
    let row = sqlx::query!(
        "SELECT status FROM peers WHERE instance_pubkey = ?",
        pubkey_slice,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::PeerNotFound))?;

    if row.status == "active" {
        operator_terminate_peer_relationship(
            &state.db,
            &state.instance_key,
            &state.instance_domain,
            &state.federation_transport,
            pubkey,
            TerminationReason::OperatorInitiated,
            None,
        )
        .await?;
        Ok(Json(DefederateResponse {
            action: "terminated".to_string(),
        }))
    } else {
        sqlx::query!("DELETE FROM peers WHERE instance_pubkey = ?", pubkey_slice)
            .execute(&state.db)
            .await?;
        Ok(Json(DefederateResponse {
            action: "removed".to_string(),
        }))
    }
}
