//! Cross-instance registration ceremony (`docs/federation-protocol.md`
//! §13 + `docs/signed-payload-format.md` §5.5).
//!
//! Surfaces two **local** API endpoints (browser ↔ destination only —
//! per §13 this is *not* a `/federation/v1/...` route, even though
//! the implementation lives next to the federation code):
//!
//! ```text
//! POST /api/auth/cross-instance/begin      — issue challenge + WebAuthn options
//! POST /api/auth/cross-instance/complete   — verify + create user + add passkey
//! ```
//!
//! ## What this ceremony is (and isn't)
//!
//! This is the **account-move** ceremony: a user who already controls
//! an Ed25519 keypair on some *other* prismoire instance proves
//! possession of that key to *this* instance and gets a fresh local
//! account anchored to the same public key. It is **not** the
//! happy-path for brand-new sign-ups (that's `auth::signup_*`), and
//! per current product policy it does **not** require an invite —
//! possession of an existing federated identity is the moral
//! equivalent of an invite.
//!
//! ## Two challenge nonces, two tables
//!
//! The ceremony interlocks two pieces of state on the destination:
//!
//! 1. **§5.5 `registration-challenge`** — a server-issued, user-signed
//!    canonical CBOR payload bound to `(user_key, dest_instance_key,
//!    dest_domain, nonce, created_at)`. The nonce lives in
//!    `registration_challenges` with single-use bookkeeping
//!    (`consumed_at` flips to non-NULL on first complete). The browser
//!    carries the entire payload bytes from begin → complete so the
//!    same canonical bytes that were signed are re-presented for
//!    verification.
//!
//! 2. **WebAuthn registration ceremony state** — a `PasskeyRegistration`
//!    blob produced by `webauthn.start_passkey_registration` and
//!    consumed by `finish_passkey_registration`. Stored in
//!    `auth_challenges` under the `'cross_instance_register'`
//!    discriminator (precedent: 'registration' for new signups,
//!    'authentication' for login, 'discoverable' for discoverable
//!    login). The `auth_challenges.id` is returned to the browser as
//!    `challenge_id` and round-trips back on complete.
//!
//! The §5.5 nonce and the `challenge_id` are independent random
//! values; they are paired on the destination via the same complete
//! request body. There is no cryptographic linkage between the two
//! beyond "the same browser submitted both, against the same `users`
//! row pre-allocated by begin." This is sufficient because each one
//! independently authorises a different effect: the §5.5 proves
//! control of the federated identity, the WebAuthn ceremony provisions
//! a *local* credential the user can log back in with after session
//! expiry.
//!
//! ## Spec vs. impl-plan placement
//!
//! `docs/federation-impl-plan.md` Phase 7 lists
//! `POST /federation/v1/register-challenge`. The spec is explicit
//! (§13): *"There is no `/federation/v1/register` or
//! `/federation/v1/challenge` route between instances. The
//! challenge-issue endpoint exists on the destination but is hit by
//! the user's browser directly; it's a local API, not a federation
//! route."* We defer to the spec and mount under `/api/auth/...`. The
//! module lives here because §13 wire-format (§5.5 challenge,
//! §12 move publication, eventual §14 recovery probing for §13.3
//! prior-home reconciliation) is conceptually federation mechanics,
//! just exposed on the local surface.
//!
//! ## Optional §12 Move publication
//!
//! If the user supplies `move_from_domain` on complete, the
//! destination attempts to author + publish a §12 Move declaration
//! pointing from that source instance to itself. The Move is signed
//! with the user's imported private key (we just verified the user
//! controls it), persisted into `signed_objects` + `user_moves` +
//! `user_homes`, then fanned out to interested peers via
//! [`forward_signed_object`].
//!
//! This is **best-effort and gated on peer knowledge.** Per §12 the
//! Move payload binds `from_instance_key` (the source instance's
//! Ed25519 pubkey) into the canonical bytes; we can only look that
//! up from our `peers` table, so move publication is silently skipped
//! when the source domain isn't an active peer. §13.3 prior-home
//! reconciliation (which would resolve the source pubkey via §14
//! recovery probing) lands in Phase 9; until then, "user moved from
//! a non-peered source" is recorded only as the local users row with
//! no associated Move chain.
//!
//! ## Out of Phase-7 scope (deferred)
//!
//! - **§13.3 prior-home reconciliation.** Depends on §14 recovery
//!   endpoints (Phase 9). The current user-declared `move_from_domain`
//!   is the pragmatic stand-in until §14 lets us probe peers.
//!
//! ## Reject reason vocabulary (§13.2)
//!
//! `expired_challenge | wrong_destination_key | wrong_destination_domain
//!  | nonce_replay | invalid_signature`; plus locally-introduced
//! `schema_invalid` (challenge bytes don't parse as §5.5) and
//! `key_mismatch` (supplied private key's pubkey ≠ challenge `user_key`).
//! Display-name validation surfaces via the existing
//! [`crate::error::ErrorCode`] vocabulary used by `auth::signup_complete`
//! so the frontend can reuse its error UX.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header::SET_COOKIE;
use axum::response::IntoResponse;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{PasskeyRegistration, RegisterPublicKeyCredential};

use crate::AppState;
use crate::auth::{LocalUserBootstrap, SessionResponse, bootstrap_local_user};
use crate::display_name::{display_name_skeleton, validate_display_name};
use crate::error::{AppError, ErrorCode};
use crate::federation::envelope::encode_signed_object;
use crate::federation::forwarder::forward_signed_object;
use crate::federation::routing::ForwardingClass;
use crate::session::{create_session, session_cookie};
use crate::signed::{self, RegistrationChallenge, SignedPayload};
use crate::signing;

/// §13.5 `REGISTRATION_CHALLENGE_TTL`: issuance-to-verify window.
/// 600 s default; rejected with `expired_challenge`.
pub const REGISTRATION_CHALLENGE_TTL_MS: u64 = 600_000;

/// §13.5 `REGISTRATION_NONCE_BYTES`: CSPRNG-issued nonce length.
/// Pinned in the schema's `CHECK (length(nonce) = 32)` constraint;
/// this constant just gives the issuance path the same number to read.
pub const REGISTRATION_NONCE_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// `POST /api/auth/cross-instance/begin` body.
#[derive(Deserialize)]
pub struct BeginRequest {
    /// Desired display name on this instance. Validated by
    /// [`validate_display_name`] and checked for uniqueness against
    /// both `users.display_name` and `users.display_name_skeleton`
    /// before any state is allocated.
    pub display_name: String,
    /// Hex-encoded 32-byte Ed25519 public key the user already
    /// controls (typically derived from a private key they exported
    /// from their previous instance). The browser will be asked to
    /// sign the returned `registration_challenge` bytes with the
    /// matching private key on complete.
    pub user_key: String,
}

/// `POST /api/auth/cross-instance/begin` success response.
#[derive(Serialize)]
pub struct BeginResponse {
    /// UUID identifying the WebAuthn registration ceremony row in
    /// `auth_challenges`. Round-trip this on complete so the server
    /// can recover the `PasskeyRegistration` state.
    pub challenge_id: String,
    /// Canonical CBOR bytes of the §5.5 `registration-challenge`
    /// payload, base64 (standard, padded) for JSON transport. The
    /// browser MUST sign these bytes verbatim — re-encoding will
    /// produce different canonical bytes and verification will fail.
    pub registration_challenge: String,
    /// WebAuthn `PublicKeyCredentialCreationOptions` for the inline
    /// passkey-add ride-along. Flattened into the response so the
    /// browser's `navigator.credentials.create({ publicKey })` call
    /// can consume the object shape directly.
    #[serde(flatten)]
    pub options: serde_json::Value,
}

/// `POST /api/auth/cross-instance/complete` body.
#[derive(Deserialize)]
pub struct CompleteRequest {
    /// UUID from the begin response — locates the `PasskeyRegistration`
    /// state in `auth_challenges`.
    pub challenge_id: String,
    /// Canonical CBOR bytes of the §5.5 challenge the browser signed,
    /// base64-encoded. Must match a `registration_challenges` row
    /// (by `nonce`) that has not been consumed.
    pub registration_challenge: String,
    /// Raw 64-byte Ed25519 signature over `registration_challenge`,
    /// base64-encoded.
    pub signature: String,
    /// WebAuthn attestation response from the browser's
    /// `navigator.credentials.create` call.
    pub credential: RegisterPublicKeyCredential,
    /// Raw 32-byte Ed25519 *private* key bytes, base64-encoded. The
    /// server persists this in `signing_keys` so it can sign on the
    /// user's behalf for downstream signed objects (trust edges,
    /// posts, …). The user's `users.public_key` is bound to
    /// `verifying_key(private_key)` and cross-checked against the
    /// challenge's `user_key` before any DB write.
    pub private_key: String,
    /// Optional canonical domain of the source instance the user
    /// moved from. When present, the destination attempts to author
    /// a §12 Move (`from_instance = move_from_domain` →
    /// `to_instance = us`), signed with the imported private key
    /// and federated to interested peers.
    ///
    /// Best-effort: requires the source to be an `active` peer so we
    /// can resolve `from_instance_key` from `peers.instance_pubkey`.
    /// Silently skipped (with a `tracing::info!`) when the source
    /// isn't a known peer; the local user is still created.
    #[serde(default)]
    pub move_from_domain: Option<String>,
}

/// `POST /api/auth/cross-instance/complete` success body. Same shape
/// as `auth::signup_complete` returns so the frontend can reuse the
/// session-bootstrap UX path.
pub type CompleteResponse = SessionResponse;

// ---------------------------------------------------------------------------
// Hex / base64 / time helpers
// ---------------------------------------------------------------------------

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Best-effort wipe of a fixed-size byte buffer. Uses
/// [`core::ptr::write_volatile`] in a loop so the optimiser cannot
/// elide the writes as dead stores. Not a substitute for a real
/// `zeroize` crate — process memory may have already been swapped or
/// copied by upstream layers — but cheap defense-in-depth on locally
/// held seed material.
fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid mutable reference into `buf`; the
        // volatile write of a `u8` is always well-defined.
        unsafe {
            core::ptr::write_volatile(b as *mut u8, 0);
        }
    }
}

/// Same as [`zeroize_bytes`] but for a heap-backed `Vec<u8>`. Shrinks
/// the vector to zero length after the volatile wipe so any
/// subsequent inadvertent dereference observes an empty buffer.
fn zeroize_vec(v: &mut Vec<u8>) {
    zeroize_bytes(v.as_mut_slice());
    v.clear();
}

// ---------------------------------------------------------------------------
// Begin handler
// ---------------------------------------------------------------------------

/// `POST /api/auth/cross-instance/begin` (§13.1).
///
/// Validates the requested display name and the supplied `user_key`,
/// issues a §5.5 `registration-challenge` bound to this instance's
/// current identity, and starts a WebAuthn passkey-registration
/// ceremony so the user can attach a local credential on the same
/// trip. Both pieces of state outlive the request: the §5.5 nonce
/// in `registration_challenges` (single-use bookkeeping), the
/// WebAuthn state in `auth_challenges` (round-tripped via
/// `challenge_id`).
pub async fn begin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BeginRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Cheap structural validation before any DB roundtrip — a
    // malformed user_key shouldn't burn a DB query, and a malformed
    // display_name shouldn't either. We validate display_name first
    // because that's the field the user just typed in the form; the
    // user_key is browser-generated and a hex decode failure here
    // implies a frontend bug rather than user error.
    let display_name = validate_display_name(&req.display_name)
        .map_err(|msg| AppError::with_message(ErrorCode::InvalidDisplayName, msg))?;
    let skeleton = display_name_skeleton(&display_name);
    let user_key = decode_hex32(&req.user_key)
        .ok_or_else(|| AppError::with_message(ErrorCode::BadRequest, "invalid user_key"))?;

    // Display-name uniqueness pre-check. Mirrors `auth::signup_begin`
    // so the frontend gets the same fast-fail UX. Re-validated under
    // the transaction in `complete` so a racing signup can't sneak
    // through.
    let existing_name = sqlx::query!(
        "SELECT id FROM users WHERE display_name = ? OR display_name_skeleton = ?",
        display_name,
        skeleton,
    )
    .fetch_optional(&state.db)
    .await?;
    if existing_name.is_some() {
        return Err(AppError::code(ErrorCode::DisplayNameTaken));
    }

    // Defensive: if a local user already holds this public_key, refuse
    // up front — re-registering the same Ed25519 key locally would
    // attach two user rows to the same identity and break authorial
    // chain joins. Re-checked under the tx in `complete`.
    let user_key_slice: &[u8] = user_key.as_slice();
    let existing_key = sqlx::query!("SELECT id FROM users WHERE public_key = ?", user_key_slice,)
        .fetch_optional(&state.db)
        .await?;
    if existing_key.is_some() {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "user_key_taken",
        ));
    }

    // Pre-allocate the eventual users.id so the WebAuthn ceremony can
    // bind to it (webauthn-rs's `start_passkey_registration` takes the
    // UUID as `user_handle`).
    let user_uuid = Uuid::new_v4();

    let (ccr, reg_state) =
        state
            .webauthn
            .start_passkey_registration(user_uuid, &display_name, &display_name, None)?;

    // Fresh CSPRNG nonce. OsRng is the same source the rest of the
    // server uses for security-sensitive randomness; a panic here is
    // the right response to RNG failure since we can't safely issue
    // identities anymore.
    let mut nonce = [0u8; REGISTRATION_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);

    let created_at = now_ms();
    let dest_instance_key = *state.instance_key.public_bytes();
    let dest_domain = state.instance_domain.clone();

    let challenge = RegistrationChallenge {
        user_key,
        dest_instance_key,
        dest_domain,
        nonce,
        created_at,
    };
    let challenge_bytes = SignedPayload::RegistrationChallenge(challenge).encode();

    // Persist both rows. They are independent — no FK linking them —
    // because the §5.5 challenge and the WebAuthn state authorise
    // different effects and are validated independently in `complete`.
    let nonce_slice: &[u8] = nonce.as_slice();
    let created_at_db = created_at as i64;
    sqlx::query!(
        "INSERT INTO registration_challenges (nonce, user_key, created_at) \
         VALUES (?, ?, ?)",
        nonce_slice,
        user_key_slice,
        created_at_db,
    )
    .execute(&state.db)
    .await?;

    let challenge_id = Uuid::new_v4().to_string();
    let state_bytes = serde_json::to_vec(&reg_state)?;
    let user_uuid_str = user_uuid.to_string();
    sqlx::query!(
        "INSERT INTO auth_challenges (id, challenge_type, state, display_name, user_id) \
         VALUES (?, 'cross_instance_register', ?, ?, ?)",
        challenge_id,
        state_bytes,
        display_name,
        user_uuid_str,
    )
    .execute(&state.db)
    .await?;

    // FIXME (parity with `auth::signup_begin`):
    // webauthn-rs hardcodes residentKey: "discouraged" in
    // start_passkey_registration. Patch the JSON to request
    // discoverable credentials so conditional UI works on the login
    // page. Remove when webauthn-rs exposes a residentKey override.
    let mut options = serde_json::to_value(ccr)?;
    if let Some(sel) = options
        .get_mut("publicKey")
        .and_then(|pk| pk.get_mut("authenticatorSelection"))
    {
        sel["residentKey"] = serde_json::json!("preferred");
        sel["requireResidentKey"] = serde_json::json!(false);
    }

    Ok(Json(BeginResponse {
        challenge_id,
        registration_challenge: BASE64.encode(&challenge_bytes),
        options,
    }))
}

// ---------------------------------------------------------------------------
// Complete handler
// ---------------------------------------------------------------------------

/// `POST /api/auth/cross-instance/complete` (§13.2 + §13 ceremony).
///
/// Verifies the signed §5.5 challenge, finishes the WebAuthn
/// passkey-registration ceremony, consumes the nonce, creates the
/// `users` + `credentials` + `signing_keys` rows via
/// [`bootstrap_local_user`], optionally authors and publishes a §12
/// Move declaration, and returns a session cookie.
pub async fn complete(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CompleteRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Decode wire-level base64 fields first; structural errors here
    // are caller bugs (not protocol-defined reject reasons), so
    // surface as `BadRequest` with a hint.
    let challenge_bytes = BASE64
        .decode(req.registration_challenge.as_bytes())
        .map_err(|_| {
            AppError::with_message(
                ErrorCode::BadRequest,
                "registration_challenge is not valid base64",
            )
        })?;
    let signature_bytes = BASE64.decode(req.signature.as_bytes()).map_err(|_| {
        AppError::with_message(ErrorCode::BadRequest, "signature is not valid base64")
    })?;
    let mut private_key_bytes = BASE64.decode(req.private_key.as_bytes()).map_err(|_| {
        AppError::with_message(ErrorCode::BadRequest, "private_key is not valid base64")
    })?;

    // Look up the WebAuthn ceremony row and recover the
    // PasskeyRegistration state + pre-allocated user_id. The row is
    // deleted single-use below (inside the transaction) so a concurrent
    // duplicate complete loses the race and surfaces as
    // InvalidChallenge.
    let auth_row = sqlx::query!(
        "SELECT state, display_name, user_id FROM auth_challenges \
         WHERE id = ? AND challenge_type = 'cross_instance_register'",
        req.challenge_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::InvalidChallenge))?;

    let display_name = auth_row.display_name.ok_or_else(|| {
        tracing::error!("cross-instance complete: missing display_name in challenge");
        AppError::code(ErrorCode::Internal)
    })?;
    let user_id = auth_row.user_id.ok_or_else(|| {
        tracing::error!("cross-instance complete: missing user_id in challenge");
        AppError::code(ErrorCode::Internal)
    })?;
    let reg_state: PasskeyRegistration = serde_json::from_slice(&auth_row.state)?;

    // Parse the canonical §5.5 challenge.
    let parsed = SignedPayload::parse(&challenge_bytes)
        .map_err(|_| AppError::with_message(ErrorCode::BadRequest, "challenge schema_invalid"))?;
    let challenge = match parsed {
        SignedPayload::RegistrationChallenge(c) => c,
        _ => {
            return Err(AppError::with_message(
                ErrorCode::BadRequest,
                "challenge is not a registration-challenge",
            ));
        }
    };

    // §13.2 identity binding: `dest_instance_key` and `dest_domain`
    // must both match this instance's *current* state. Checked before
    // signature verify so a stale challenge from a peer rename
    // surfaces a specific diagnostic.
    if challenge.dest_instance_key != *state.instance_key.public_bytes() {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "wrong_destination_key",
        ));
    }
    if challenge.dest_domain != state.instance_domain {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "wrong_destination_domain",
        ));
    }

    // §13.2 TTL check. `expired_challenge` is terminal — the client
    // requests a fresh challenge and retries.
    let now = now_ms();
    if now.saturating_sub(challenge.created_at) > REGISTRATION_CHALLENGE_TTL_MS {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "expired_challenge",
        ));
    }

    // §13.2 signature verify. The user proves possession of
    // `challenge.user_key` by signing the canonical challenge bytes.
    let user_vk = ed25519_dalek::VerifyingKey::from_bytes(&challenge.user_key).map_err(|_| {
        AppError::with_message(
            ErrorCode::BadRequest,
            "user_key is not a valid Ed25519 pubkey",
        )
    })?;
    if signed::verify(&challenge_bytes, &signature_bytes, &user_vk).is_err() {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "invalid_signature",
        ));
    }

    // Cross-check: the supplied private_key must derive a verifying
    // key equal to challenge.user_key. This is the local-only
    // `key_mismatch` reject — a user who proved control of K_a but
    // submitted privkey-of-K_b would otherwise install K_b for
    // server-side signing, leaving K_a's chain orphaned. Catching
    // this here turns a subtle data-integrity bug into an actionable
    // 4xx.
    let mut private_key_array: [u8; 32] = private_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AppError::with_message(ErrorCode::BadRequest, "private_key length"))?;
    let imported = SigningKey::from_bytes(&private_key_array);
    // `SigningKey` clears its own internal copy on Drop, but the two
    // intermediate buffers we copied from (the base64-decoded `Vec<u8>`
    // and the `[u8; 32]` stack array) still hold the raw seed and
    // outlive this point. Volatile writes scrub them so the seed
    // doesn't linger in heap/stack after the request returns. This is
    // defense-in-depth — the bytes have already passed through axum's
    // body buffer, the JSON parser, and the base64 decoder, none of
    // which we control — but it costs nothing and shrinks the window.
    zeroize_bytes(&mut private_key_array);
    zeroize_vec(&mut private_key_bytes);
    if imported.verifying_key().to_bytes() != challenge.user_key {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "key_mismatch",
        ));
    }

    // Finish the WebAuthn registration. webauthn-rs's
    // finish_passkey_registration verifies the attestation, the
    // challenge nonce inside the credential matches what
    // start_passkey_registration issued, and so on. Any failure here
    // is the browser submitting a bogus or stale attestation, not a
    // protocol-defined §13.2 reject reason.
    let passkey = state
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)?;

    let skeleton = display_name_skeleton(&display_name);

    // Snapshot fields we'll need under the transaction or after it.
    let public_key: &[u8] = challenge.user_key.as_slice();
    let cred_id = Uuid::new_v4().to_string();
    let passkey_bytes = serde_json::to_vec(&passkey)?;
    let cred_id_bytes: &[u8] = passkey.cred_id().as_ref();

    // If the user declared a source domain, look up its instance
    // pubkey from our peers table. Only `active` peers are eligible —
    // a pending peering can't reliably express "this is the trust
    // anchor for X." A missing row is *not* an error: §13 explicitly
    // allows registration without a Move; we just skip publication
    // and the local users row exists with no associated move chain.
    //
    // The lookup is deliberately *outside* the BEGIN IMMEDIATE below.
    // The race window — peer transitions from `active` to inactive
    // between this SELECT and the tx commit — is benign: the resulting
    // Move is signed by the user's own key (it's the user's
    // cryptographic identity that authenticates the move, not the
    // peer's current status); the `from_instance_key` / `from_instance`
    // fields are spec metadata and downstream peers don't validate
    // them against the source's *current* peer status on this instance.
    let move_source: Option<([u8; 32], String)> = match req.move_from_domain.as_deref() {
        Some(domain) if !domain.is_empty() => {
            let row = sqlx::query!(
                "SELECT instance_pubkey AS \"instance_pubkey!: Vec<u8>\" \
                 FROM peers WHERE instance_domain = ? AND status = 'active' LIMIT 1",
                domain,
            )
            .fetch_optional(&state.db)
            .await?;
            match row {
                Some(r) => match <[u8; 32]>::try_from(r.instance_pubkey.as_slice()) {
                    Ok(arr) => Some((arr, domain.to_string())),
                    Err(_) => {
                        tracing::warn!(
                            domain = %domain,
                            "cross-instance complete: peers.instance_pubkey wrong length; skipping move publication"
                        );
                        None
                    }
                },
                None => {
                    tracing::info!(
                        domain = %domain,
                        "cross-instance complete: move_from_domain is not an active peer; skipping move publication"
                    );
                    None
                }
            }
        }
        _ => None,
    };

    // BEGIN IMMEDIATE: nonce-consume + auth_challenges delete + user
    // creation + (optional) move publication run as one snapshot so a
    // concurrent second complete against the same nonce loses the
    // consume race and surfaces as `nonce_replay` rather than racing
    // into a duplicate user row.
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;

    // §13.2 nonce single-use: row must exist (else the challenge
    // bytes don't match anything we issued → invalid_signature) AND
    // consumed_at must be NULL.
    let nonce_slice: &[u8] = challenge.nonce.as_slice();
    let nonce_row = sqlx::query!(
        "SELECT consumed_at, user_key AS \"user_key!: Vec<u8>\" \
         FROM registration_challenges WHERE nonce = ?",
        nonce_slice,
    )
    .fetch_optional(&mut *tx)
    .await?;
    // §13.2: every "the supplied challenge doesn't match a usable
    // server-side nonce" path collapses to `invalid_signature` on the
    // wire. Distinguishing nonce-never-issued, nonce-already-consumed,
    // and nonce-issued-for-different-key would give an attacker a
    // confirmation oracle for guessed nonces and user_key associations
    // — they could enumerate which guess landed on a previously-issued
    // row even when they don't hold the private key. Internally we log
    // the distinguishing reason so an operator triaging registration
    // failures can still tell the cases apart.
    let nonce_row = nonce_row.ok_or_else(|| {
        tracing::info!(
            user_key_prefix = ?&challenge.user_key[..4],
            "cross-instance complete rejected: nonce not present"
        );
        AppError::with_message(ErrorCode::BadRequest, "invalid_signature")
    })?;
    if nonce_row.consumed_at.is_some() {
        tracing::info!(
            user_key_prefix = ?&challenge.user_key[..4],
            "cross-instance complete rejected: nonce already consumed (replay)"
        );
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "invalid_signature",
        ));
    }
    if nonce_row.user_key.as_slice() != challenge.user_key.as_slice() {
        tracing::info!(
            user_key_prefix = ?&challenge.user_key[..4],
            "cross-instance complete rejected: nonce was issued for a different user_key"
        );
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "invalid_signature",
        ));
    }

    sqlx::query!(
        "UPDATE registration_challenges \
         SET consumed_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE nonce = ?",
        nonce_slice,
    )
    .execute(&mut *tx)
    .await?;

    // Delete the WebAuthn ceremony row single-use. If a concurrent
    // complete already deleted it, our row count is 0 — that means
    // the other complete won the race, and we should refuse rather
    // than half-build a second user. SQLx surfaces zero-affected as
    // success, so re-check via the explicit row-count from
    // `rows_affected`.
    let deleted = sqlx::query!("DELETE FROM auth_challenges WHERE id = ?", req.challenge_id,)
        .execute(&mut *tx)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(AppError::code(ErrorCode::InvalidChallenge));
    }

    // Re-check user_key uniqueness under the transaction snapshot.
    let existing_key_tx = sqlx::query!("SELECT id FROM users WHERE public_key = ?", public_key,)
        .fetch_optional(&mut *tx)
        .await?;
    if existing_key_tx.is_some() {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "user_key_taken",
        ));
    }

    // Re-check display_name uniqueness under the transaction snapshot
    // so a racing signup can't sneak in between the pre-tx check in
    // `begin` and here.
    let existing_name_tx = sqlx::query!(
        "SELECT id FROM users WHERE display_name = ? OR display_name_skeleton = ?",
        display_name,
        skeleton,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if existing_name_tx.is_some() {
        return Err(AppError::code(ErrorCode::DisplayNameTaken));
    }

    bootstrap_local_user(
        &mut tx,
        &LocalUserBootstrap {
            user_id: &user_id,
            display_name: &display_name,
            display_name_skeleton: &skeleton,
            signup_method: "cross_instance_register",
            public_key,
            signing_key: &imported,
            credential_id: &cred_id,
            passkey_credential_id: cred_id_bytes,
            passkey_bytes: &passkey_bytes,
        },
    )
    .await?;

    // §12 Move publication. Authored only when we resolved the source
    // peer above; in-tx so a rollback nukes the move alongside the
    // user. Forwarder is invoked AFTER commit so a fanout that
    // somehow blocks doesn't hold the write transaction.
    let move_for_forward: Option<([u8; 32], Vec<u8>)> =
        if let Some((from_key, from_domain)) = move_source {
            let to_instance_key = *state.instance_key.public_bytes();
            let to_instance = state.instance_domain.clone();
            let signed_move = signing::sign_move_with_key(
                &imported,
                &from_key,
                &from_domain,
                &to_instance_key,
                &to_instance,
                now,
                None, // §13-originated moves are the user's first move from us
            );

            signing::store_signed_object(
                &mut *tx,
                "move",
                &signed_move.payload,
                &signed_move.signature,
                &signed_move.canonical_hash,
            )
            .await?;

            // Project into user_moves (§12.3 backfill index).
            let key_slice: &[u8] = challenge.user_key.as_slice();
            let canonical_hash_db: Vec<u8> = signed_move.canonical_hash.to_vec();
            let created_at_db = now as i64;
            sqlx::query!(
                "INSERT OR IGNORE INTO user_moves (user_key, canonical_hash, created_at) \
             VALUES (?, ?, ?)",
                key_slice,
                canonical_hash_db,
                created_at_db,
            )
            .execute(&mut *tx)
            .await?;

            // UPSERT user_homes — we're the §12.4 winner by construction
            // (we just signed `to_instance = us` with the freshest
            // timestamp). If a future inbound move with a later
            // `created_at` arrives, the receive path will overwrite us.
            let to_key_db: Vec<u8> = to_instance_key.to_vec();
            sqlx::query!(
                "INSERT INTO user_homes \
                (user_key, current_home_key, current_home_domain, \
                 current_move_hash, current_created_at) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(user_key) DO UPDATE SET \
                current_home_key = excluded.current_home_key, \
                current_home_domain = excluded.current_home_domain, \
                current_move_hash = excluded.current_move_hash, \
                current_created_at = excluded.current_created_at, \
                updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
                key_slice,
                to_key_db,
                to_instance,
                canonical_hash_db,
                created_at_db,
            )
            .execute(&mut *tx)
            .await?;

            let wire = encode_signed_object(&signed_move.payload, &signed_move.signature);
            Some((signed_move.canonical_hash, wire))
        } else {
            None
        };

    tx.commit().await?;

    // §12.2 unconditional flood, post-commit so a slow fanout can't
    // hold the write tx. `arrived_from = None` because we are the
    // originator. Routing-key for moves is the moving identity K
    // (§7.4 + §12).
    if let Some((canonical_hash, wire)) = move_for_forward {
        forward_signed_object(
            state.clone(),
            canonical_hash,
            ForwardingClass::Move,
            challenge.user_key.to_vec(),
            wire,
            None,
        )
        .await;
    }

    let token = create_session(&state.db, &user_id).await?;
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, session_cookie(&token).parse().unwrap());

    Ok((
        headers,
        Json(SessionResponse::active(
            user_id,
            display_name,
            "user".into(),
            crate::settings::DEFAULT_THEME.into(),
            crate::settings::DEFAULT_FONT.into(),
        )),
    ))
}

// ---------------------------------------------------------------------------
// Layer-0 unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_constant_matches_spec() {
        // §13.5: REGISTRATION_CHALLENGE_TTL default 600 s.
        assert_eq!(REGISTRATION_CHALLENGE_TTL_MS, 600_000);
    }

    #[test]
    fn nonce_size_constant_matches_spec() {
        // §13.5: REGISTRATION_NONCE_BYTES default 32.
        assert_eq!(REGISTRATION_NONCE_BYTES, 32);
    }

    #[test]
    fn decode_hex32_round_trips() {
        let s = "deadbeef".repeat(8);
        let bytes = decode_hex32(&s).expect("decode");
        assert_eq!(bytes.len(), 32);
        // hex 0xde 0xad 0xbe 0xef …
        assert_eq!(&bytes[0..4], &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn decode_hex32_rejects_wrong_length() {
        assert!(decode_hex32("deadbeef").is_none());
        assert!(decode_hex32(&"de".repeat(33)).is_none());
    }

    #[test]
    fn decode_hex32_rejects_non_hex() {
        let bad = format!("{}gg", "de".repeat(31));
        assert!(decode_hex32(&bad).is_none());
    }
}
