//! GDPR privacy endpoints: data export and account self-deletion.
//!
//! Both endpoints accept `RestrictedAuthUser` so banned/suspended users can
//! still exercise their right-to-access and right-to-erasure — a GDPR
//! requirement, not a moderation decision.
//!
//! # Export (`GET /api/me/export`)
//!
//! Returns a JSON payload with everything in `schema.sql` that belongs to
//! the caller: user row, settings, credentials, signing keypairs
//! (public + private), outbound trust edges, invites they created, threads
//! and posts they authored (with every revision), reports they filed, and
//! moderation actions taken against them. Inbound trust edges and other
//! users' content are NOT included — those are the authoring user's data.
//!
//! Session tokens are deliberately excluded: they are live auth credentials
//! that would grant account access to anyone who got hold of an export file.
//!
//! Attachment blob *bytes* are emitted by a companion endpoint —
//! `GET /api/me/export/attachments` — which returns a ZIP archive of the
//! user's uploaded files plus a self-describing `MANIFEST.json` mapping
//! each blob back to its bindings. The split keeps the JSON small and
//! lets users download just the metadata or just the bytes; see
//! `docs/attachments.md` §8.
//!
//! # Delete (`DELETE /api/me`)
//!
//! Soft-deletes the user:
//!
//! - Retracts every non-retracted post (one signed retraction per post,
//!   bodies nulled — same shape as `posts::retract_post`).
//! - Clears the user's content from the FTS5 search tables
//!   (`posts_fts`, `threads_fts.op_body`) so `/search` does not leak
//!   the indexed text of retracted posts after deletion.
//! - Anonymises the `users` row: display_name becomes `deleted-<hex>`,
//!   bio nulled, `deleted_at` set, `can_invite = 0`.
//! - Drops credentials, sessions, user_settings, auth_challenges, and
//!   *all* trust_edges touching the user (both outbound and inbound).
//!   Outbound edges stop flowing the deleted user's trust signal
//!   through the graph; inbound edges are dropped too because the
//!   deleted user can no longer author content, so a standing trust
//!   endorsement of them has nothing to weigh anymore and would only
//!   serve as latent noise in the trust graph.
//! - Erases canonical bytes of every signed `profile` revision the
//!   user authored, then drops the projection rows. The display_name
//!   and bio snapshots in `profile_revisions` are personal data; the
//!   `users` row anonymisation alone would leak them via the signed-
//!   object history.
//! - Drops `ban_trust_snapshots` rows referencing the user in either
//!   capacity (target of a past ban/suspend, or a truster captured at
//!   the moment someone else was moderated). Same rationale: with the
//!   account gone, those snapshot rows have nothing to describe.
//! - Sweeps every `attachment_staging` row the user uploaded (§7.a of
//!   `docs/attachments.md`) and GCs any `attachment_blobs` row that
//!   reaches `refcount = 0` without a remaining staging anchor.
//!   Bindings on the user's still-visible posts were already dropped
//!   by the retraction cascade, so this step picks up the remaining
//!   staged-but-unbound and now-orphan blobs.
//! - NULLs `attachment_blobs.uploader` on every surviving blob the user
//!   uploaded (§7.b). Severs the personal-data link "this user
//!   uploaded these bytes" on blobs that another user has independently
//!   uploaded the same SHA-256 of and bound to a still-live post.
//! - Drops the user's `user_storage_budgets` row (§7.c). The
//!   `lifetime_spent` / `available_bytes` figures are account-scoped
//!   state with nothing to associate with once the account is
//!   anonymized.
//! - Revokes any open invites the user created.
//! - Deactivates signing keys (`active = 0`) rather than deleting them, so
//!   past signatures on content still authored by other users remain
//!   verifiable.
//!
//! The row itself stays for FK integrity — rooms, threads, posts, reports,
//! and admin_log all reference `users.id`. The `deleted_at` tombstone is
//! what gates UI rendering ("[deleted]") and login attempts downstream.
//!
//! # Inbound federated moderation evidence is deliberately excluded
//!
//! Three tables can name a *local* user as the subject of moderation
//! evidence that *another instance* authored and pushed to us:
//!
//! - `federated_reports.target_author` — a remote reporter's §18 report
//!   against a post one of our users wrote.
//! - `user_statuses.subject` — a remote home instance's §16 ban/suspend
//!   of a user (only meaningful for users whose home is elsewhere, but
//!   the column shape admits a local subject).
//! - `admin_rm_reports` — the pre-existing local precedent: reports
//!   filed *against* a user, as opposed to `reports` filed *by* them.
//!
//! None of these are emitted by `GET /api/me/export` or touched by
//! `DELETE /api/me`, and that omission is intentional, not an oversight
//! of the "keep `privacy.rs` in sync with the schema" rule:
//!
//! - **It is not the subject's personal data to access or erase.** A
//!   report or status is a *signed assertion authored by another party*
//!   (a remote reporter, a remote home instance) about the subject. The
//!   author's right to make and retain that assertion — and the
//!   recipient instance's legitimate interest in moderation and abuse
//!   prevention (GDPR Art. 6(1)(f), Art. 17(3)) — outweighs the
//!   subject's erasure interest in evidence held *against* them. Letting
//!   a banned user erase the federated ban that targets them would
//!   defeat the moderation surface entirely.
//! - **We are not its controller in the relevant sense.** The canonical
//!   record lives at the authoring instance; our copy is received
//!   moderation state. An erasure request belongs at the home/authoring
//!   instance, which is the §16/§18 source of truth.
//! - **Consistency with the existing precedent.** `admin_rm_reports`
//!   has never been exported or erased for exactly this reason; the
//!   Phase-11 federated tables follow the same line so the local and
//!   federated moderation surfaces are treated identically.
//!
//! Note the asymmetry with `reports` *filed by* the user, which **are**
//! exported (they are the user's own authored assertions) — see the
//! `reports_filed: Vec<ReportExport>` field below. The distinction is
//! authorship: you can access/erase what you asserted, not what was
//! asserted about you.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use base64::Engine;
use ed25519_dalek::SigningKey;
use serde::Serialize;
use uuid::Uuid;

use crate::attachments;
use crate::display_name::display_name_skeleton;
use crate::error::{AppError, ErrorCode};
use crate::session::{RestrictedAuthUser, clear_session_cookie};
use crate::signing::sign_retraction_with_key;
use crate::state::AppState;

/// Wire version of the export payload. Bump whenever the shape changes so
/// downstream tools can branch on it.
///
/// v2 (2026-05): adds per-revision `attachments` on `PostRevisionExport`,
/// plus top-level `pending_attachments`, `storage_budget`, and
/// `attachments_blob_archive`. See `docs/attachments.md` §8.1.
const EXPORT_VERSION: u32 = 2;

/// Companion-endpoint pointer baked into `DataExport.attachments_blob_archive`.
/// Reminds anyone parsing the JSON without UI context that the blob bytes
/// live in the ZIP at `GET /api/me/export/attachments`. See
/// `docs/attachments.md` §8.1.
const ATTACHMENTS_BLOB_ARCHIVE_PATH: &str = "/api/me/export/attachments";

// ---------------------------------------------------------------------------
// Export response types
// ---------------------------------------------------------------------------

/// Top-level wrapper for a user data export.
///
/// Everything in this struct is derived from rows the caller owns. See the
/// module docstring for the intentional exclusions (session tokens, inbound
/// trust edges, other users' content).
#[derive(Serialize)]
pub struct DataExport {
    pub export_version: u32,
    pub exported_at: String,
    pub user: UserExport,
    pub settings: SettingsExport,
    pub credentials: Vec<CredentialExport>,
    pub signing_keys: Vec<SigningKeyExport>,
    pub trust_edges_outbound: Vec<TrustEdgeExport>,
    pub profile_revisions: Vec<ProfileRevisionExport>,
    pub invites_created: Vec<InviteExport>,
    pub threads: Vec<ThreadExport>,
    pub posts: Vec<PostExport>,
    pub reports_filed: Vec<ReportExport>,
    pub moderation_actions_against_me: Vec<AdminLogExport>,
    pub favorite_rooms: Vec<FavoriteRoomExport>,
    pub user_tags_set: Vec<UserTagExport>,
    /// Staged-but-unbound uploads the user owns. Each row is a blob the
    /// user uploaded to the staging area but didn't yet bind to a post
    /// (or whose binding was edited away before the staging TTL ran).
    /// Included so the export covers every user-owned attachment-side
    /// row, not just bindings reachable via a post-revision.
    pub pending_attachments: Vec<PendingAttachmentExport>,
    /// Per-user storage allowance state. Always emitted; a missing
    /// `user_storage_budgets` row maps to the zero-default struct so
    /// readers can rely on the field's presence.
    pub storage_budget: StorageBudgetExport,
    /// Pointer to the companion ZIP endpoint that carries the actual
    /// blob bytes. The JSON export deliberately omits the bytes (the
    /// metadata side is small and easy to read; the bytes belong in a
    /// streamable ZIP). Always set to `/api/me/export/attachments`.
    pub attachments_blob_archive: String,
    /// Federation §12 identity-move history for this user. One entry
    /// per row in `user_moves` keyed on the user's pubkey, ordered
    /// oldest-first. The currently-applied move (the one whose
    /// `to_instance_key` is reflected in `user_homes.current_home_key`)
    /// is flagged via `is_current`. Empty for users who have never
    /// moved between instances. Phase 7 GDPR fold-in.
    pub home_history: Vec<UserMoveExport>,
    /// In-flight §13.1 registration challenges keyed on the user's
    /// pubkey. Normally empty — the row is consumed on `complete` and
    /// otherwise GC'd within
    /// [`crate::session::REGISTRATION_CHALLENGE_MAX_AGE_MS`](../session/index.html)
    /// of issuance. A non-empty list here means someone (often the
    /// user themselves, on a retry) recently started a cross-instance
    /// registration against this user_key.
    pub registration_challenges: Vec<RegistrationChallengeExport>,
}

#[derive(Serialize)]
pub struct UserExport {
    pub id: String,
    pub display_name: String,
    pub display_name_skeleton: String,
    pub created_at: String,
    pub signup_method: String,
    pub steam_verified: bool,
    pub status: String,
    pub role: String,
    pub bio: Option<String>,
    pub invite_id: Option<String>,
    pub inviter_display_name: Option<String>,
    pub can_invite: bool,
    pub suspended_until: Option<String>,
    /// Tombstone timestamp set when the account has been self-deleted.
    /// Always `None` for a live export (the exporter must be logged in,
    /// and deleted users can't log in), but included so the payload
    /// covers every user-owned column in `users`.
    pub deleted_at: Option<String>,
    /// Ed25519 public key, base64url (no padding). This is the
    /// canonical federation-identity column for the user.
    pub public_key_b64: String,
    /// Home-instance pubkey, base64url (no padding). NULL means homed
    /// at this instance; a remote instance pubkey would appear here
    /// for federated accounts. Always NULL for any user who can call
    /// this endpoint (federated users have no local session).
    pub home_instance_b64: Option<String>,
}

#[derive(Serialize)]
pub struct SettingsExport {
    pub theme: String,
    pub font: String,
}

#[derive(Serialize)]
pub struct CredentialExport {
    pub id: String,
    /// WebAuthn credential id, base64url (no padding).
    pub credential_id_b64: String,
    /// Serialized `webauthn_rs::Passkey` blob (JSON), base64url (no padding).
    pub public_key_b64: String,
    pub sign_count: i64,
    pub created_at: String,
    pub last_used: String,
    pub label: Option<String>,
}

#[derive(Serialize)]
pub struct SigningKeyExport {
    pub id: String,
    /// Ed25519 private key, base64url (no padding). Sensitive — treat the
    /// export file as you would a private key on disk.
    ///
    /// The matching public key lives on `user.public_key_b64`(top-level
    /// `UserExport`).
    pub private_key_b64: String,
    pub created_at: String,
    pub active: bool,
}

#[derive(Serialize)]
pub struct TrustEdgeExport {
    pub id: String,
    pub target_user_id: String,
    pub target_display_name: String,
    pub trust_type: String,
    pub created_at: String,
    pub reason: Option<String>,
}

/// One signed profile revision authored by the exporting user.
///
/// The signed-object content (display_name + bio + avatar) is
/// projection data — the same payload is also recoverable by
/// re-parsing the canonical CBOR from `signed_objects.payload`. We
/// emit it as projection so an export reader doesn't need a CBOR
/// decoder to read their own profile history.
#[derive(Serialize)]
pub struct ProfileRevisionExport {
    pub id: String,
    pub display_name: String,
    pub bio: String,
    pub avatar_attachment_hash_b64: Option<String>,
    /// Authored time in Unix milliseconds. Stored as INTEGER in the
    /// DB rather than ISO-8601 text so the same value can be the
    /// `created_at` field of the canonical CBOR payload.
    pub created_at_ms: i64,
    pub prior_profile_hash_b64: Option<String>,
    pub canonical_hash_b64: String,
}

#[derive(Serialize)]
pub struct InviteExport {
    pub id: String,
    pub code: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub max_uses: Option<i64>,
    pub expires_at: Option<String>,
}

#[derive(Serialize)]
pub struct ThreadExport {
    pub id: String,
    pub title: String,
    pub room_slug: String,
    pub created_at: String,
    pub locked: bool,
    pub reply_count: i64,
    pub link_url: Option<String>,
    /// Home-instance pubkey, base64url (no padding). NULL for
    /// locally-authored threads. Populated when the federation receive
    /// path lands; included here so the export covers every
    /// user-owned column in `threads`.
    pub home_instance_b64: Option<String>,
}

#[derive(Serialize)]
pub struct PostRevisionExport {
    pub revision: i64,
    pub body: String,
    /// Ed25519 signature over the revision body, base64url (no padding).
    pub signature_b64: String,
    pub created_at: String,
    /// Attachments bound to this specific revision, in `position` order.
    /// Per-revision rather than per-post because the edit path (§6 of
    /// `docs/attachments.md`) lets each revision carry a different set;
    /// the export preserves the full history. Empty for revisions with
    /// no attachments.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentExport>,
}

/// One attachment binding as it appeared on a specific post revision.
///
/// `content_hash_b64` is the identity field — the matching bytes live
/// in the companion ZIP at `blobs/<short-hash>-<sanitized-filename>`
/// (see `docs/attachments.md` §8.2). `filename` is per-binding (the
/// same blob can be referenced by two posts under different names);
/// inline-vs-download display is now derived from `![](name)` body
/// references at render time rather than carried in the binding row.
#[derive(Serialize)]
pub struct AttachmentExport {
    pub content_hash_b64: String,
    pub size: i64,
    pub mime: String,
    pub filename: String,
}

/// One staged-but-unbound upload owned by the exporting user.
///
/// Distinct from `AttachmentExport` because there is no post binding
/// yet — only the staging anchor + the underlying blob row. Will become
/// a regular binding (and migrate into a `PostRevisionExport.attachments`
/// entry) the first time it gets bound to a post.
#[derive(Serialize)]
pub struct PendingAttachmentExport {
    pub content_hash_b64: String,
    pub size: i64,
    pub mime: String,
    pub expires_at: String,
    pub created_at: String,
}

/// One §12 move row from this instance's chain index.
///
/// Mirrors `user_moves` joined to the originating `signed_objects`
/// row so the export carries every wire field of the move (not just
/// the projection). `is_current` is set on the row whose
/// `canonical_hash` matches `user_homes.current_move_hash` — the
/// winner of §12.4 latest-wins resolution at export time.
#[derive(Serialize)]
pub struct UserMoveExport {
    pub canonical_hash_b64: String,
    /// Wire `created_at` in Unix milliseconds (copied verbatim from
    /// the signed move payload).
    pub created_at_ms: i64,
    /// Signed CBOR payload, base64url (no padding). `None` only if a
    /// downstream erasure NULL'd the row — moves are §12.5
    /// indefinite-retention so this should be `Some` in practice.
    pub payload_b64: Option<String>,
    /// Detached Ed25519 signature, base64url (no padding).
    pub signature_b64: String,
    /// True iff this is the active home per §12.4 latest-wins (i.e.
    /// `user_homes.current_move_hash == canonical_hash`).
    pub is_current: bool,
}

/// One pending §13.1 registration challenge row. Surfaces the wire
/// `created_at` (Unix ms) and whether the nonce has been consumed; the
/// raw 32-byte nonce is base64-encoded for completeness, since the
/// row's PII content (the user's own pubkey) is already in `user`.
#[derive(Serialize)]
pub struct RegistrationChallengeExport {
    pub nonce_b64: String,
    pub created_at_ms: i64,
    pub consumed_at: Option<String>,
}

/// Per-user storage allowance state. Mirrors `user_storage_budgets`.
/// Zero-default when the user has never triggered the row's lazy creation
/// (no uploads yet) so the export field is always present.
#[derive(Serialize)]
pub struct StorageBudgetExport {
    pub available_bytes: i64,
    pub last_refill_at: String,
    pub lifetime_spent: i64,
}

#[derive(Serialize)]
pub struct PostExport {
    pub id: String,
    pub thread_id: String,
    pub parent_id: Option<String>,
    pub created_at: String,
    pub retracted_at: Option<String>,
    pub revisions: Vec<PostRevisionExport>,
    /// Home-instance pubkey, base64url (no padding). NULL for
    /// locally-authored posts. Populated when the federation receive
    /// path lands; included here so the export covers every
    /// user-owned column in `posts`.
    pub home_instance_b64: Option<String>,
}

#[derive(Serialize)]
pub struct ReportExport {
    pub id: String,
    pub post_id: String,
    pub reason: String,
    pub detail: Option<String>,
    pub status: String,
    pub created_at: String,
    pub resolved_at: Option<String>,
}

#[derive(Serialize)]
pub struct FavoriteRoomExport {
    pub room_slug: String,
    pub position: i64,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct UserTagExport {
    pub target_user_id: String,
    pub target_display_name: String,
    pub tag: String,
    pub updated_at: String,
}

#[derive(Serialize)]
pub struct AdminLogExport {
    pub id: String,
    pub action: String,
    pub reason: Option<String>,
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// GET /api/me/export
// ---------------------------------------------------------------------------

/// Return the full GDPR data export for the current user.
///
/// Available to banned and suspended users — right-to-access is not gated on
/// moderation status.
#[allow(clippy::type_complexity)]
pub async fn export_my_data(
    State(state): State<Arc<AppState>>,
    user: RestrictedAuthUser,
) -> Result<impl IntoResponse, AppError> {
    let db = &state.db;
    let user_id = user.user_id.as_str();

    let user_row = sqlx::query!(
        r#"SELECT id, display_name, display_name_skeleton, created_at, signup_method,
           steam_verified AS "steam_verified!: bool", status, role, bio, invite_id,
           can_invite AS "can_invite!: bool", suspended_until, deleted_at,
           public_key, home_instance
           FROM users WHERE id = ?"#,
        user_id,
    )
    .fetch_one(db)
    .await?;

    // Resolve the inviter's display name if we have an invite_id.
    let inviter_display_name: Option<String> = if let Some(iid) = user_row.invite_id.as_deref() {
        sqlx::query!(
            "SELECT u.display_name FROM invites i \
             JOIN users u ON u.id = i.created_by \
             WHERE i.id = ?",
            iid,
        )
        .fetch_optional(db)
        .await?
        .map(|r| r.display_name)
    } else {
        None
    };

    let settings_row = sqlx::query!(
        r#"SELECT
            COALESCE((SELECT theme FROM user_settings WHERE user_id = ?), 'rose-pine') AS "theme!: String",
            COALESCE((SELECT font FROM user_settings WHERE user_id = ?), 'literata') AS "font!: String""#,
        user_id,
        user_id,
    )
    .fetch_one(db)
    .await?;
    let theme = settings_row.theme;
    let font = settings_row.font;

    let credential_rows = sqlx::query!(
        "SELECT id, credential_id, public_key, sign_count, created_at, last_used, label \
         FROM credentials WHERE user_id = ? ORDER BY created_at ASC",
        user_id,
    )
    .fetch_all(db)
    .await?;

    let credentials: Vec<CredentialExport> = credential_rows
        .into_iter()
        .map(|r| CredentialExport {
            id: r.id,
            credential_id_b64: b64(&r.credential_id),
            public_key_b64: b64(&r.public_key),
            sign_count: r.sign_count,
            created_at: r.created_at,
            last_used: r.last_used,
            label: r.label,
        })
        .collect();

    let signing_key_rows = sqlx::query!(
        r#"SELECT id, private_key, created_at, active AS "active!: bool"
         FROM signing_keys WHERE user_id = ? ORDER BY created_at ASC"#,
        user_id,
    )
    .fetch_all(db)
    .await?;

    let signing_keys: Vec<SigningKeyExport> = signing_key_rows
        .into_iter()
        .map(|r| SigningKeyExport {
            id: r.id,
            private_key_b64: b64(&r.private_key),
            created_at: r.created_at,
            active: r.active,
        })
        .collect();

    let trust_edge_rows = sqlx::query!(
        "SELECT te.id, te.target_user, u.display_name, te.trust_type, te.created_at, te.reason \
         FROM trust_edges te \
         JOIN users u ON u.id = te.target_user \
         WHERE te.source_user = ? \
         ORDER BY te.created_at ASC",
        user_id,
    )
    .fetch_all(db)
    .await?;

    let trust_edges_outbound: Vec<TrustEdgeExport> = trust_edge_rows
        .into_iter()
        .map(|r| TrustEdgeExport {
            id: r.id,
            target_user_id: r.target_user,
            target_display_name: r.display_name,
            trust_type: r.trust_type,
            created_at: r.created_at,
            reason: r.reason,
        })
        .collect();

    // Signed profile revisions. Sorted by `created_at` ascending so the
    // export reads as a natural chain head-to-current. Hash columns are
    // emitted as base64 (the rest of the export emits BLOBs the same way
    // via the `b64` helper).
    let profile_revision_rows = sqlx::query!(
        r#"SELECT id, display_name, bio,
                  avatar_attachment_hash AS "avatar_attachment_hash?: Vec<u8>",
                  created_at AS "created_at!: i64",
                  prior_profile_hash AS "prior_profile_hash?: Vec<u8>",
                  canonical_hash AS "canonical_hash!: Vec<u8>"
           FROM profile_revisions
           WHERE user_id = ?
           ORDER BY created_at ASC, id ASC"#,
        user_id,
    )
    .fetch_all(db)
    .await?;

    let profile_revisions: Vec<ProfileRevisionExport> = profile_revision_rows
        .into_iter()
        .map(|r| ProfileRevisionExport {
            id: r.id,
            display_name: r.display_name,
            bio: r.bio,
            avatar_attachment_hash_b64: r.avatar_attachment_hash.as_deref().map(b64),
            created_at_ms: r.created_at,
            prior_profile_hash_b64: r.prior_profile_hash.as_deref().map(b64),
            canonical_hash_b64: b64(&r.canonical_hash),
        })
        .collect();

    let invite_rows = sqlx::query!(
        "SELECT id, code, created_at, revoked_at, max_uses, expires_at \
         FROM invites WHERE created_by = ? ORDER BY created_at ASC",
        user_id,
    )
    .fetch_all(db)
    .await?;

    let invites_created: Vec<InviteExport> = invite_rows
        .into_iter()
        .map(|r| InviteExport {
            id: r.id,
            code: r.code,
            created_at: r.created_at,
            revoked_at: r.revoked_at,
            max_uses: r.max_uses,
            expires_at: r.expires_at,
        })
        .collect();

    let thread_rows = sqlx::query!(
        r#"SELECT t.id, t.title, r.slug, t.created_at, t.locked AS "locked!: bool", t.reply_count, t.link_url, t.home_instance
         FROM threads t
         JOIN rooms r ON r.id = t.room
         WHERE t.author = ?
         ORDER BY t.created_at ASC"#,
        user_id,
    )
    .fetch_all(db)
    .await?;

    let threads: Vec<ThreadExport> = thread_rows
        .into_iter()
        .map(|r| ThreadExport {
            id: r.id,
            title: r.title,
            room_slug: r.slug,
            created_at: r.created_at,
            locked: r.locked,
            reply_count: r.reply_count,
            link_url: r.link_url,
            home_instance_b64: r.home_instance.as_deref().map(b64),
        })
        .collect();

    let post_rows = sqlx::query!(
        "SELECT id, thread, parent, created_at, retracted_at, home_instance \
         FROM posts WHERE author = ? ORDER BY created_at ASC",
        user_id,
    )
    .fetch_all(db)
    .await?;

    let mut posts: Vec<PostExport> = Vec::with_capacity(post_rows.len());
    for post_row in post_rows {
        let revision_rows = sqlx::query!(
            "SELECT revision, body, signature, created_at \
             FROM post_revisions WHERE post_id = ? ORDER BY revision ASC",
            post_row.id,
        )
        .fetch_all(db)
        .await?;

        // Attachments are per-revision (`docs/attachments.md` §6); a
        // single query gathers every revision's bindings for this
        // post, joined to `attachment_blobs` for `size` + `mime`. The
        // result is bucketed by `revision` below so each
        // `PostRevisionExport` sees only its own bindings.
        let attachment_rows = sqlx::query!(
            r#"SELECT pa.revision AS "revision!: i64",
                      pa.position AS "position!: i64",
                      pa.content_hash AS "content_hash!: Vec<u8>",
                      pa.filename AS "filename!: String",
                      ab.size AS "size!: i64",
                      ab.content_type AS "mime!: String"
                 FROM post_attachments pa
                 JOIN attachment_blobs ab ON ab.content_hash = pa.content_hash
                WHERE pa.post_id = ?
                ORDER BY pa.revision ASC, pa.position ASC"#,
            post_row.id,
        )
        .fetch_all(db)
        .await?;

        let mut attachments_by_revision: std::collections::HashMap<i64, Vec<AttachmentExport>> =
            std::collections::HashMap::new();
        for ar in attachment_rows {
            attachments_by_revision
                .entry(ar.revision)
                .or_default()
                .push(AttachmentExport {
                    content_hash_b64: b64(&ar.content_hash),
                    size: ar.size,
                    mime: ar.mime,
                    filename: ar.filename,
                });
        }

        let revisions = revision_rows
            .into_iter()
            .map(|r| PostRevisionExport {
                attachments: attachments_by_revision
                    .remove(&r.revision)
                    .unwrap_or_default(),
                revision: r.revision,
                body: r.body,
                signature_b64: b64(&r.signature),
                created_at: r.created_at,
            })
            .collect();

        posts.push(PostExport {
            id: post_row.id,
            thread_id: post_row.thread,
            parent_id: post_row.parent,
            created_at: post_row.created_at,
            retracted_at: post_row.retracted_at,
            revisions,
            home_instance_b64: post_row.home_instance.as_deref().map(b64),
        });
    }

    let report_rows = sqlx::query!(
        "SELECT id, post_id, reason, detail, status, created_at, resolved_at \
         FROM reports WHERE reporter = ? ORDER BY created_at ASC",
        user_id,
    )
    .fetch_all(db)
    .await?;

    let reports_filed: Vec<ReportExport> = report_rows
        .into_iter()
        .map(|r| ReportExport {
            id: r.id,
            post_id: r.post_id,
            reason: r.reason,
            detail: r.detail,
            status: r.status,
            created_at: r.created_at,
            resolved_at: r.resolved_at,
        })
        .collect();

    // Moderation actions where the user is the target. Only action +
    // reason + timestamp are exported — referenced post/thread/room ids
    // stay out so the export does not leak other users' content.
    let admin_log_rows = sqlx::query!(
        "SELECT id, action, reason, created_at \
         FROM admin_log WHERE target_user = ? ORDER BY created_at ASC",
        user_id,
    )
    .fetch_all(db)
    .await?;

    let moderation_actions_against_me: Vec<AdminLogExport> = admin_log_rows
        .into_iter()
        .map(|r| AdminLogExport {
            id: r.id,
            action: r.action,
            reason: r.reason,
            created_at: r.created_at,
        })
        .collect();

    let favorite_rows = sqlx::query!(
        "SELECT r.slug, f.position, f.created_at \
         FROM room_favorites f \
         JOIN rooms r ON r.id = f.room_id \
         WHERE f.user_id = ? \
         ORDER BY f.position ASC",
        user_id,
    )
    .fetch_all(db)
    .await?;

    let favorite_rooms: Vec<FavoriteRoomExport> = favorite_rows
        .into_iter()
        .map(|r| FavoriteRoomExport {
            room_slug: r.slug,
            position: r.position,
            created_at: r.created_at,
        })
        .collect();

    // Private viewer-scoped tags the user has attached to other users.
    // Strictly the caller's data — these were never visible to anyone
    // else, including the tagged users themselves.
    let user_tag_rows = sqlx::query!(
        "SELECT ut.target_id, u.display_name, ut.tag, ut.updated_at \
         FROM user_tags ut \
         JOIN users u ON u.id = ut.target_id \
         WHERE ut.viewer_id = ? \
         ORDER BY ut.updated_at ASC",
        user_id,
    )
    .fetch_all(db)
    .await?;

    let user_tags_set: Vec<UserTagExport> = user_tag_rows
        .into_iter()
        .map(|r| UserTagExport {
            target_user_id: r.target_id,
            target_display_name: r.display_name,
            tag: r.tag,
            updated_at: r.updated_at,
        })
        .collect();

    // Staged-but-unbound uploads the user owns. Each row anchors a
    // blob the user uploaded but hasn't (yet) bound to a post; the
    // join to `attachment_blobs` pulls `size` + `mime` for the
    // export. Bytes are intentionally NOT selected — they belong in
    // the companion ZIP. See `docs/attachments.md` §8.1.
    let pending_rows = sqlx::query!(
        r#"SELECT s.content_hash AS "content_hash!: Vec<u8>",
                  s.expires_at AS "expires_at!: String",
                  s.created_at AS "created_at!: String",
                  ab.size AS "size!: i64",
                  ab.content_type AS "mime!: String"
             FROM attachment_staging s
             JOIN attachment_blobs ab ON ab.content_hash = s.content_hash
            WHERE s.uploader = ?
            ORDER BY s.created_at ASC"#,
        user_id,
    )
    .fetch_all(db)
    .await?;

    let pending_attachments: Vec<PendingAttachmentExport> = pending_rows
        .into_iter()
        .map(|r| PendingAttachmentExport {
            content_hash_b64: b64(&r.content_hash),
            size: r.size,
            mime: r.mime,
            expires_at: r.expires_at,
            created_at: r.created_at,
        })
        .collect();

    // Per-user storage allowance. Missing row → zero-default struct
    // so the export field is always present (users who have never
    // uploaded anything haven't triggered the lazy row creation).
    let budget_row = sqlx::query!(
        "SELECT available_bytes, last_refill_at, lifetime_spent \
         FROM user_storage_budgets WHERE user_id = ?",
        user_id,
    )
    .fetch_optional(db)
    .await?;

    let storage_budget = match budget_row {
        Some(r) => StorageBudgetExport {
            available_bytes: r.available_bytes,
            last_refill_at: r.last_refill_at,
            lifetime_spent: r.lifetime_spent,
        },
        None => StorageBudgetExport {
            available_bytes: 0,
            last_refill_at: String::new(),
            lifetime_spent: 0,
        },
    };

    // §12 home history. `user_moves` rows joined back to
    // `signed_objects` so we get payload + signature alongside the
    // index columns. Ordered oldest-first to match the natural reading
    // order of a migration history. `is_current` marks the row that
    // §12.4 latest-wins resolution promoted to `user_homes`; that
    // lookup may return no row at all (never-moved local users have no
    // `user_homes` entry), in which case no row is flagged.
    let public_key_bytes: &[u8] = user_row.public_key.as_slice();
    let move_rows = sqlx::query!(
        r#"SELECT um.canonical_hash AS "canonical_hash!: Vec<u8>",
                  um.created_at AS "created_at_ms!: i64",
                  so.payload AS "payload?: Vec<u8>",
                  so.signature AS "signature!: Vec<u8>"
             FROM user_moves um
             JOIN signed_objects so ON so.canonical_hash = um.canonical_hash
            WHERE um.user_key = ?
            ORDER BY um.created_at ASC"#,
        public_key_bytes,
    )
    .fetch_all(db)
    .await?;
    let current_move_hash_row = sqlx::query!(
        r#"SELECT current_move_hash AS "current_move_hash!: Vec<u8>"
             FROM user_homes WHERE user_key = ?"#,
        public_key_bytes,
    )
    .fetch_optional(db)
    .await?;
    let current_hash = current_move_hash_row.map(|r| r.current_move_hash);
    let home_history: Vec<UserMoveExport> = move_rows
        .into_iter()
        .map(|r| {
            let is_current = current_hash
                .as_deref()
                .is_some_and(|cur| cur == r.canonical_hash.as_slice());
            UserMoveExport {
                canonical_hash_b64: b64(&r.canonical_hash),
                created_at_ms: r.created_at_ms,
                payload_b64: r.payload.as_deref().map(b64),
                signature_b64: b64(&r.signature),
                is_current,
            }
        })
        .collect();

    // §13.1 in-flight registration challenges keyed on the user's
    // pubkey. Almost always empty (consumed-or-GC'd within an hour);
    // included for completeness so the export covers every
    // user-key-indexed row in the schema.
    let challenge_rows = sqlx::query!(
        r#"SELECT nonce AS "nonce!: Vec<u8>",
                  created_at AS "created_at_ms!: i64",
                  consumed_at AS "consumed_at?: String"
             FROM registration_challenges
            WHERE user_key = ?
            ORDER BY created_at ASC"#,
        public_key_bytes,
    )
    .fetch_all(db)
    .await?;
    let registration_challenges: Vec<RegistrationChallengeExport> = challenge_rows
        .into_iter()
        .map(|r| RegistrationChallengeExport {
            nonce_b64: b64(&r.nonce),
            created_at_ms: r.created_at_ms,
            consumed_at: r.consumed_at,
        })
        .collect();

    let exported_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let export = DataExport {
        export_version: EXPORT_VERSION,
        exported_at,
        user: UserExport {
            id: user_row.id,
            display_name: user_row.display_name,
            display_name_skeleton: user_row.display_name_skeleton,
            created_at: user_row.created_at,
            signup_method: user_row.signup_method,
            steam_verified: user_row.steam_verified,
            status: user_row.status,
            role: user_row.role,
            bio: user_row.bio,
            invite_id: user_row.invite_id,
            inviter_display_name,
            can_invite: user_row.can_invite,
            suspended_until: user_row.suspended_until,
            deleted_at: user_row.deleted_at,
            public_key_b64: b64(&user_row.public_key),
            home_instance_b64: user_row.home_instance.as_deref().map(b64),
        },
        settings: SettingsExport { theme, font },
        credentials,
        signing_keys,
        trust_edges_outbound,
        profile_revisions,
        invites_created,
        threads,
        posts,
        reports_filed,
        moderation_actions_against_me,
        favorite_rooms,
        user_tags_set,
        pending_attachments,
        storage_budget,
        attachments_blob_archive: ATTACHMENTS_BLOB_ARCHIVE_PATH.to_string(),
        home_history,
        registration_challenges,
    };

    // Suggest a filename to the browser so "Save as…" is one click. The
    // standard `Content-Type: application/json` still lets the frontend
    // parse the body when it invokes the endpoint via `fetch`.
    //
    // Display names may contain Unicode that `HeaderValue` can't hold
    // (non-ASCII, or quote/control characters that would break the
    // `filename="..."` quoting). Reduce to a conservative ASCII subset
    // and fall back to the opaque user id if nothing printable remains.
    let safe_name = sanitize_filename_stem(&export.user.display_name);
    let stem = if safe_name.is_empty() {
        export.user.id.clone()
    } else {
        safe_name
    };
    let filename = format!("prismoire-export-{stem}.json");
    let disposition = format!("attachment; filename=\"{filename}\"");

    let mut headers = HeaderMap::new();
    // Sanitization above guarantees this is ASCII with no control chars,
    // so the `HeaderValue` parse cannot fail.
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        disposition.parse().unwrap(),
    );

    Ok((headers, Json(export)))
}

/// Reduce a display name to a conservative ASCII filename stem.
///
/// Keeps ASCII alphanumerics, dot, dash, and underscore; everything else
/// (including Unicode letters, spaces, quotes, and control characters) is
/// dropped. The output is always safe to put inside a `filename="..."`
/// `Content-Disposition` header without further escaping.
fn sanitize_filename_stem(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect()
}

// ---------------------------------------------------------------------------
// GET /api/me/export/attachments
// ---------------------------------------------------------------------------

/// Wire shape of one blob record inside the ZIP's `MANIFEST.json`.
///
/// See `docs/attachments.md` §8.2: one entry per unique content hash
/// (dedup is preserved). `bindings` lists every still-visible binding the
/// exporting user authored; `staging` is true iff the blob was uploaded
/// but never bound (a "pending" upload — `attachment_staging` row).
#[derive(Serialize)]
struct ZipManifestBlob {
    content_hash_b64: String,
    file_name_in_zip: String,
    size: i64,
    mime: String,
    bindings: Vec<ZipManifestBinding>,
    staging: bool,
}

#[derive(Serialize)]
struct ZipManifestBinding {
    post_id: String,
    revision: i64,
    position: i64,
    filename: String,
}

#[derive(Serialize)]
struct ZipManifest {
    export_version: u32,
    exported_at: String,
    user_id: String,
    /// Pointer to the companion JSON metadata export. Same intent as
    /// `DataExport.attachments_blob_archive` in the opposite direction:
    /// a user opening only the ZIP can find where the metadata lives.
    metadata_archive: String,
    blobs: Vec<ZipManifestBlob>,
}

/// Stream the user's attachment bytes as a ZIP.
///
/// Companion to `GET /api/me/export`: the JSON export carries the
/// per-binding metadata and points here via
/// `attachments_blob_archive`. The ZIP carries the actual bytes plus a
/// self-describing `MANIFEST.json` that maps each blob back to the
/// bindings it satisfies. See `docs/attachments.md` §8.2.
///
/// Available to banned and suspended users (same precedent as
/// `export_my_data`). Users with zero attachments still get a valid
/// ZIP — empty `blobs/` directory + a `MANIFEST.json` with an empty
/// `blobs` array. Clearer than disabling the button with no
/// explanation.
pub async fn export_my_attachments(
    State(state): State<Arc<AppState>>,
    user: RestrictedAuthUser,
) -> Result<impl IntoResponse, AppError> {
    let db = &state.db;
    let user_id = user.user_id.as_str();

    // Load the user's display name for the suggested ZIP filename.
    // Reuses the same `sanitize_filename_stem` pass as the JSON export
    // so the two file names are visibly twinned in the user's downloads
    // folder.
    let user_row = sqlx::query!("SELECT display_name FROM users WHERE id = ?", user_id)
        .fetch_one(db)
        .await?;

    // Bindings authored by this user: one row per (post, revision,
    // position). Joined to `post_revisions` so we have the
    // `created_at` we need to pick the most-recent binding's filename
    // per blob (§8.2 "which user-filename does a blob get").
    let binding_rows = sqlx::query!(
        r#"SELECT pa.post_id AS "post_id!: String",
                  pa.revision AS "revision!: i64",
                  pa.position AS "position!: i64",
                  pa.content_hash AS "content_hash!: Vec<u8>",
                  pa.filename AS "filename!: String",
                  pr.created_at AS "rev_created_at!: String"
             FROM post_attachments pa
             JOIN posts p ON p.id = pa.post_id
             JOIN post_revisions pr ON pr.post_id = pa.post_id AND pr.revision = pa.revision
            WHERE p.author = ?"#,
        user_id,
    )
    .fetch_all(db)
    .await?;

    // Staging anchors owned by this user (uploads not yet bound).
    let staging_rows = sqlx::query!(
        r#"SELECT content_hash AS "content_hash!: Vec<u8>"
             FROM attachment_staging
            WHERE uploader = ?"#,
        user_id,
    )
    .fetch_all(db)
    .await?;

    // Union of every content_hash the user owns through either path.
    // BTreeMap so iteration is stable (sort by hash) — gives the ZIP
    // a deterministic entry order independent of SQLite's internal
    // row layout, which keeps test fixtures reproducible.
    use std::collections::BTreeMap;
    let mut hashes_owned: BTreeMap<Vec<u8>, ()> = BTreeMap::new();
    for r in &binding_rows {
        hashes_owned.insert(r.content_hash.clone(), ());
    }
    for r in &staging_rows {
        hashes_owned.insert(r.content_hash.clone(), ());
    }

    // Bucket bindings by content_hash so each blob can be rendered
    // with its full bindings array in the manifest.
    let mut bindings_by_hash: std::collections::HashMap<Vec<u8>, Vec<ZipManifestBinding>> =
        std::collections::HashMap::new();
    // Track each blob's "winning" filename — the one written into
    // `blobs/<short-hash>-<filename>` and into `file_name_in_zip`.
    // Per spec: most recent revision, ties broken by post id ASC,
    // then position ASC.
    // Store `(rev_created_at, post_id, position)` and pick the
    // promotion winner via the custom comparison below — we want max
    // on `rev_created_at` and min on the tiebreakers, so a plain
    // lex-order tuple comparison doesn't fit. Explicit branching is
    // clearer than encoding negated keys for `Reverse`.
    type WinningKey = (String, String, i64);
    let mut winning_filename: std::collections::HashMap<Vec<u8>, (WinningKey, String)> =
        std::collections::HashMap::new();
    for r in binding_rows {
        let key: WinningKey = (r.rev_created_at.clone(), r.post_id.clone(), r.position);
        let entry = winning_filename
            .entry(r.content_hash.clone())
            .or_insert_with(|| (key.clone(), r.filename.clone()));
        // Most-recent revision wins. Tie: smaller post_id and smaller
        // position win. So we want: max rev_created_at, then min post_id,
        // then min position. Promote when strictly better.
        let is_better = match key.0.cmp(&entry.0.0) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => match key.1.cmp(&entry.0.1) {
                std::cmp::Ordering::Less => true,
                std::cmp::Ordering::Greater => false,
                std::cmp::Ordering::Equal => key.2 < entry.0.2,
            },
        };
        if is_better {
            *entry = (key, r.filename.clone());
        }

        bindings_by_hash
            .entry(r.content_hash)
            .or_default()
            .push(ZipManifestBinding {
                post_id: r.post_id,
                revision: r.revision,
                position: r.position,
                filename: r.filename,
            });
    }

    // Stabilise per-blob binding lists by (revision asc, position asc).
    // Same idea as the hash-level sort: deterministic output regardless
    // of how the DB returned the rows.
    for v in bindings_by_hash.values_mut() {
        v.sort_by(|a, b| {
            a.post_id
                .cmp(&b.post_id)
                .then_with(|| a.revision.cmp(&b.revision))
                .then_with(|| a.position.cmp(&b.position))
        });
    }

    // Pull every blob the user owns. `ab.blob` is `Option<Vec<u8>>`
    // because the column is nullable (federation-received placeholders
    // and a few §5 erasure paths leave the bytes NULL); we still emit
    // a manifest record with the bytes absent for such rows so the
    // user sees "this blob exists / was federated, but its bytes are
    // not stored locally" rather than the row vanishing silently.
    //
    // Using `?1` twice with the same bound parameter mirrors the spec
    // §8.2 query; sqlx allows positional bindings via `?N`.
    let blob_rows = sqlx::query!(
        r#"WITH user_blobs AS (
            SELECT DISTINCT pa.content_hash
              FROM post_attachments pa
              JOIN posts p ON p.id = pa.post_id
             WHERE p.author = ?
            UNION
            SELECT s.content_hash FROM attachment_staging s WHERE s.uploader = ?
           )
           SELECT ab.content_hash AS "content_hash!: Vec<u8>",
                  ab.blob AS "blob?: Vec<u8>",
                  ab.content_type AS "mime!: String",
                  ab.size AS "size!: i64"
             FROM attachment_blobs ab
             JOIN user_blobs ub ON ub.content_hash = ab.content_hash"#,
        user_id,
        user_id,
    )
    .fetch_all(db)
    .await?;

    // Index blob rows by content_hash so the deterministic loop below
    // can look up the bytes / mime / size for each owned hash.
    struct BlobEntry {
        blob: Option<Vec<u8>>,
        mime: String,
        size: i64,
    }
    let mut blob_by_hash: std::collections::HashMap<Vec<u8>, BlobEntry> =
        std::collections::HashMap::with_capacity(blob_rows.len());
    for r in blob_rows {
        blob_by_hash.insert(
            r.content_hash,
            BlobEntry {
                blob: r.blob,
                mime: r.mime,
                size: r.size,
            },
        );
    }

    // Walk hashes in deterministic order (BTreeMap key order = hash
    // bytewise ascending) and assemble the manifest + ZIP entry list.
    // We carry the bytes through as well so `spawn_blocking` can write
    // the archive without re-touching the DB.
    let mut manifest_blobs: Vec<ZipManifestBlob> = Vec::with_capacity(hashes_owned.len());
    let mut zip_entries: Vec<(String, Option<Vec<u8>>)> = Vec::with_capacity(hashes_owned.len());
    // Disambiguate identical sanitized filenames across different blobs
    // (e.g. two screenshots both sanitized to `screenshot.png`). The
    // short-hash prefix already differs per blob, so the full
    // `<short-hash>-<filename>` is unique, but if two blobs collide on
    // the same short-hash *and* same sanitized filename (vanishingly
    // unlikely at 48 bits but possible) we'd produce duplicate ZIP
    // entries which is a hard error. Track seen names to detect that.
    let mut seen_entry_names: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(hashes_owned.len());
    for (content_hash, _) in hashes_owned {
        let BlobEntry { blob, mime, size } = match blob_by_hash.remove(&content_hash) {
            Some(t) => t,
            // Defensive: a hash present in bindings/staging but missing
            // from `attachment_blobs` would indicate a torn schema state.
            // Skip the row rather than aborting the export — the manifest
            // alone is still useful.
            None => {
                tracing::warn!(
                    user_id = %user_id,
                    hash = %short_hash_hex(&content_hash),
                    "attachment hash referenced by user but missing from attachment_blobs",
                );
                continue;
            }
        };

        let bindings = bindings_by_hash.remove(&content_hash).unwrap_or_default();
        let staging = bindings.is_empty();

        // Pick the user-visible filename for this blob, then build the
        // full ZIP entry name `blobs/<short-hash>-<sanitized>`.
        let raw_name = winning_filename.remove(&content_hash).map(|(_, name)| name);
        let entry_filename = zip_entry_filename(&content_hash, raw_name.as_deref(), &mime);
        let entry_path = format!("blobs/{entry_filename}");

        // Hard-collision guard (see comment on `seen_entry_names`).
        // The short-hash prefix gives us 48 bits of separation, so a
        // collision means two distinct content hashes happened to share
        // the same 12 hex prefix AND sanitize to the same suffix. In
        // that case fall back to a full-hex prefix. A second collision
        // on the full-hex form would require two distinct content
        // hashes to share their entire 256-bit hex prefix, which is
        // impossible (we iterate over a set keyed on `content_hash`),
        // so we assert it as a tripwire — silent duplicates would
        // produce an invalid ZIP.
        let final_path = if seen_entry_names.insert(entry_path.clone()) {
            entry_path
        } else {
            let full_hex = attachments::hex_encode(&content_hash);
            let collision_path = format!("blobs/{full_hex}-{entry_filename}");
            tracing::warn!(
                user_id = %user_id,
                short_hash = %short_hash_hex(&content_hash),
                "short-hash collision in ZIP export; falling back to full-hex prefix",
            );
            let inserted = seen_entry_names.insert(collision_path.clone());
            debug_assert!(
                inserted,
                "full-hex ZIP entry collision: distinct content_hashes share a 256-bit prefix"
            );
            collision_path
        };
        let final_filename = final_path
            .strip_prefix("blobs/")
            .unwrap_or(&final_path)
            .to_string();

        manifest_blobs.push(ZipManifestBlob {
            content_hash_b64: b64(&content_hash),
            file_name_in_zip: final_filename,
            size,
            mime,
            bindings,
            staging,
        });
        zip_entries.push((final_path, blob));
    }

    let exported_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let manifest = ZipManifest {
        export_version: EXPORT_VERSION,
        exported_at,
        user_id: user_id.to_string(),
        metadata_archive: "/api/me/export".to_string(),
        blobs: manifest_blobs,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize attachments-export manifest");
        AppError::code(ErrorCode::Internal)
    })?;

    // ZIP encoding is CPU-bound (deflate) and the `zip` crate is
    // synchronous, so the assembly runs in `spawn_blocking`. Per-blob
    // memory is bounded by `MAX_ATTACHMENT_SIZE` (500 KiB); the in-
    // memory buffer is the user's whole archive at once, which is
    // bounded by `lifetime_spent` per the storage-budget design.
    //
    // We use STORE (no compression) — every supported MIME (PNG, JPEG,
    // WebP, PDF, txt with a 500 KiB cap) is either already compressed
    // or small enough that deflate wouldn't meaningfully shrink it.
    // Deflate would just burn CPU.
    let zip_bytes = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, std::io::Error> {
        use std::io::Write;
        use zip::ZipWriter;
        use zip::write::SimpleFileOptions;

        let mut cursor = std::io::Cursor::new(Vec::<u8>::with_capacity(64 * 1024));
        let mut writer = ZipWriter::new(&mut cursor);
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            // SimpleFileOptions defaults the version-needed-to-extract
            // and general-purpose bit-flag based on filename contents;
            // the `zip` crate sets the UTF-8 flag automatically when
            // the entry name is not pure ASCII, so non-ASCII filenames
            // (e.g. `🦀.rs`) decode correctly.
            .large_file(false);

        // Manifest goes first so a partial download (e.g. broken
        // connection mid-ZIP) still hands the user something
        // interpretable: knowing which blobs were *supposed* to be in
        // the archive is more useful than half a blob.
        writer.start_file("MANIFEST.json", opts)?;
        writer.write_all(&manifest_bytes)?;

        for (path, blob) in zip_entries {
            writer.start_file(&path, opts)?;
            if let Some(bytes) = blob {
                writer.write_all(&bytes)?;
            }
            // NULL blob: emit a zero-byte entry. The manifest's `size`
            // field still reflects the *intended* size; consumers
            // detect the discrepancy and can surface "bytes
            // unavailable" without us inventing a sentinel format.
        }

        // `finish` consumes the writer and returns the inner sink
        // (`&mut Cursor`) — drop the returned ref so the outer
        // `cursor.into_inner()` can take ownership.
        let _ = writer.finish()?;
        Ok(cursor.into_inner())
    })
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "attachments ZIP build task panicked");
        AppError::code(ErrorCode::Internal)
    })?
    .map_err(|e| {
        tracing::error!(error = %e, "attachments ZIP build I/O error");
        AppError::code(ErrorCode::Internal)
    })?;

    // Suggested filename, mirroring the JSON export's convention.
    let safe_name = sanitize_filename_stem(&user_row.display_name);
    let stem = if safe_name.is_empty() {
        user_id.to_string()
    } else {
        safe_name
    };
    let filename = format!("prismoire-attachments-{stem}.zip");
    let disposition = format!("attachment; filename=\"{filename}\"");

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        "application/zip".parse().unwrap(),
    );
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        disposition.parse().unwrap(),
    );

    Ok((headers, zip_bytes))
}

/// First 12 hex chars of a content hash, lowercase. 48 bits — collision-
/// proof at any plausible per-user archive size while staying readable
/// in directory listings. See `docs/attachments.md` §8.2.
fn short_hash_hex(content_hash: &[u8]) -> String {
    let mut s = String::with_capacity(12);
    for b in content_hash.iter().take(6) {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// MIME → conventional filename extension for staging-only blobs that
/// have no user-supplied filename. Restricted to the five members of
/// `ALLOWED_MIMES`; anything else falls back to `.bin` (which the
/// schema constraints make unreachable today, but acts as a defensive
/// default if the allowlist later grows).
fn mime_to_extension(mime: &str) -> &'static str {
    match mime {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/webp" => "webp",
        "text/plain" => "txt",
        "application/pdf" => "pdf",
        _ => "bin",
    }
}

/// Sanitize a user-supplied filename for safe inclusion as a ZIP entry.
///
/// Stricter than the bind-time §2.2 pass because ZIP entries become
/// real filesystem paths at extraction time:
/// - strip path separators (`/`, `\`) — zip-slip defense
/// - strip NUL + ASCII control characters
/// - strip leading dots — no hidden files on Unix extraction
/// - strip Windows-reserved characters (`< > : " | ? *`)
/// - truncate to 80 UTF-8 bytes at a char boundary
///
/// UTF-8 is preserved; the `zip` crate sets the encoding flag based on
/// entry-name content. Returns the empty string if sanitization removes
/// everything — callers fall back to `<short-hash>.<ext>`.
fn sanitize_zip_entry_name(name: &str) -> String {
    let filtered: String = name
        .chars()
        .filter(|c| {
            !matches!(c, '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*') && !c.is_control()
        })
        .collect();
    // Strip leading dots after filtering: a filename like ".hidden" should
    // become "hidden", and "..." should become "" (then fall back).
    let trimmed = filtered.trim_start_matches('.');

    // Truncate at an 80-byte limit, respecting UTF-8 char boundaries.
    if trimmed.len() <= 80 {
        return trimmed.to_string();
    }
    let mut end = 80;
    while end > 0 && !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    trimmed[..end].to_string()
}

/// Pick the `<short-hash>-<sanitized-user-filename>` for one blob.
///
/// `raw_name` is the winning binding's filename (per §8.2's
/// most-recent-binding rule), or `None` for staging-only blobs. Falls
/// back to `<short-hash>.<ext>` when the user filename sanitizes to
/// empty or doesn't exist at all.
fn zip_entry_filename(content_hash: &[u8], raw_name: Option<&str>, mime: &str) -> String {
    let short = short_hash_hex(content_hash);
    let sanitized = raw_name.map(sanitize_zip_entry_name).unwrap_or_default();
    if sanitized.is_empty() {
        format!("{short}.{}", mime_to_extension(mime))
    } else {
        format!("{short}-{sanitized}")
    }
}

// ---------------------------------------------------------------------------
// DELETE /api/me
// ---------------------------------------------------------------------------

/// Delete the current user's account and associated personal data.
///
/// See the module docstring for the full list of operations. Clears the
/// session cookie on the response so the browser immediately forgets the
/// dead session.
pub async fn delete_my_account(
    State(state): State<Arc<AppState>>,
    user: RestrictedAuthUser,
) -> Result<impl IntoResponse, AppError> {
    let mut tx = state.db.begin().await?;
    let fanout = soft_delete_user(&mut tx, &user.user_id).await?;
    tx.commit().await?;

    // §7.5 originator-side fanout for every signed retract + the
    // umbrella deactivate. Happens strictly after commit so a rollback
    // can't ship ghosts.
    forward_deactivation(&state, fanout).await;

    // Trust graph drops the deleted user's outbound edges on the next
    // rebuild.
    state.trust_graph_notify.notify_one();

    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, clear_session_cookie().parse().unwrap());

    Ok((StatusCode::NO_CONTENT, headers))
}

/// Federation fanout payload returned by [`soft_delete_user`].
///
/// One per-post `retract` plus (optionally) one umbrella `deactivate`,
/// each carrying the wire bytes + routing key + canonical hash needed
/// to drive [`crate::federation::forwarder::forward_signed_object`].
/// Callers MUST invoke the fanout *after* the soft-delete transaction
/// commits — otherwise a tx rollback would ship signed objects to peers
/// that the local instance never persisted, polluting the federated
/// view with ghosts that pull-backfill would later 410-Gone.
///
/// The struct is returned even when empty (e.g. the user had no active
/// signing key to sign retractions / deactivate with); the caller
/// passes it through unconditionally and the helper no-ops.
pub(crate) struct DeactivationFanout {
    pub items: Vec<FanoutItem>,
}

/// One signed object ready for §7.5 originator-side fanout.
pub(crate) struct FanoutItem {
    pub canonical_hash: [u8; 32],
    pub routing_key: Vec<u8>,
    pub wire: Vec<u8>,
}

/// Run §7.5 originator-side fanout for every item produced by
/// [`soft_delete_user`]. ForwardingClass::Authored for all of them
/// (per-post `retract` and umbrella `deactivate` are both author-keyed
/// classes per §7.4). Call this AFTER the deletion tx commits.
///
/// Phase 6.4.1: awaited inline by callers — the per-item enqueue is
/// `Mutex` + `Notify` and never blocks on egress, so handler latency
/// is bounded by the candidate-selection DB queries (one per item).
pub(crate) async fn forward_deactivation(state: &Arc<AppState>, fanout: DeactivationFanout) {
    for item in fanout.items {
        crate::federation::forwarder::forward_signed_object(
            state.clone(),
            item.canonical_hash,
            crate::federation::routing::ForwardingClass::Authored,
            item.routing_key,
            item.wire,
            None,
        )
        .await;
    }
}

/// Shared soft-delete implementation used by both the self-deletion
/// endpoint (`DELETE /api/me`) and the admin-initiated delete action
/// (`DELETE /api/admin/users/{id}`).
///
/// Performs every step described in the module docstring: retracts all
/// still-visible posts with signed retractions, anonymises the `users`
/// row, and drops credentials, sessions, user_settings, trust_edges,
/// ban_trust_snapshots, auth_challenges; revokes open invites; and
/// deactivates signing keys. Idempotent against re-entry after a crash
/// via the `deleted_at IS NULL` guard on the anonymise UPDATE.
///
/// Caller owns the transaction: this helper runs every statement on the
/// supplied transaction but does not commit. That lets the
/// admin-initiated caller emit its `admin_log` entry in the same
/// transaction as the deletion, so there is no "user deleted but no
/// audit entry written" window on a mid-flight crash.
///
/// Returns a [`DeactivationFanout`] capturing the per-post `retract`
/// and (when an active signing key exists) the umbrella `deactivate`
/// signed objects that the caller MUST hand to
/// [`forward_deactivation`] after committing the tx. The helper itself
/// is federation-unaware to keep the (tx + state) coupling out of its
/// signature.
///
/// Does **not** notify the trust graph or touch any session cookie —
/// those concerns are handled by the calling endpoint, which has the
/// request context (`AppState`, `HeaderMap`) that this helper doesn't
/// want to depend on.
pub(crate) async fn soft_delete_user(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: &str,
) -> Result<DeactivationFanout, AppError> {
    // Load the active signing key first so we can sign every post
    // retraction before touching the destructive statements. This keeps
    // retraction signatures faithful to the spec ("retraction does not
    // destroy accountability — the original signature remains
    // cryptographically valid"). The SELECT runs on the caller's
    // transaction so it sees the same snapshot as the later UPDATEs.
    let key_row = sqlx::query!(
        "SELECT private_key FROM signing_keys WHERE user_id = ? AND active = 1",
        user_id,
    )
    .fetch_optional(&mut **tx)
    .await?;

    let signing_key = match key_row {
        Some(row) => {
            let key_bytes: [u8; 32] = row.private_key.try_into().map_err(|v: Vec<u8>| {
                tracing::error!(
                    user_id = %user_id,
                    length = v.len(),
                    "privacy::soft_delete_user: signing key has invalid length (expected 32)"
                );
                AppError::code(ErrorCode::Internal)
            })?;
            Some(SigningKey::from_bytes(&key_bytes))
        }
        None => None,
    };

    // Anonymised display name. 16 hex chars = 64 bits of entropy, well
    // clear of collisions even across millions of deletions. Skeleton
    // has to be unique too (idx_users_display_name_skeleton), so we
    // derive it from the same anonymised string.
    let anon_suffix = Uuid::new_v4().simple().to_string()[..16].to_string();
    let anon_name = format!("deleted-{anon_suffix}");
    let anon_skeleton = display_name_skeleton(&anon_name);

    // Find every post that still needs retracting. Runs inside the
    // caller-owned transaction so a concurrent post creation between
    // SELECT and UPDATE can't leave a fresh post un-retracted.
    let posts_to_retract = sqlx::query!(
        "SELECT id FROM posts WHERE author = ? AND retracted_at IS NULL",
        user_id,
    )
    .fetch_all(&mut **tx)
    .await?;

    // One producer-side timestamp shared across all of this user's
    // retractions: bulk deletion is atomic as far as the user is
    // concerned, and binding the same instant in every signed
    // retraction is fine. Truncated to whole seconds for the same
    // reason as the per-handler retract path — see
    // posts.rs::retract_post.
    let now_dt = chrono::Utc::now();
    let retracted_at = now_dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let created_at_ms = (now_dt.timestamp() as u64) * 1000;

    // Pre-compute retraction signatures in memory so the subsequent
    // UPDATEs are pure DB work (signing is CPU-only and does not touch
    // the pool, so doing it inside the tx is fine). The optional
    // `signed_bytes` carries the canonical payload + hash for the
    // dual-write into `signed_objects` (None when no active key).
    // We also collect a parallel `fanout_items` vec: every signed
    // retract becomes a §7.5 originator-fanout entry; the umbrella
    // `deactivate` is appended below once it's signed.
    type RetractionRow = (String, Vec<u8>, Option<(Vec<u8>, [u8; 32])>);
    let mut fanout_items: Vec<FanoutItem> = Vec::new();
    let retractions: Vec<RetractionRow> = if let Some(key) = signing_key.as_ref() {
        posts_to_retract
            .into_iter()
            .map(|r| {
                let post_uuid = Uuid::parse_str(&r.id).map_err(|e| {
                    tracing::error!(post_id = %r.id, error = %e, "invalid post UUID in row");
                    AppError::code(ErrorCode::Internal)
                })?;
                let out = sign_retraction_with_key(key, &post_uuid, created_at_ms);
                let wire =
                    crate::federation::envelope::encode_signed_object(&out.payload, &out.signature);
                fanout_items.push(FanoutItem {
                    canonical_hash: out.canonical_hash,
                    routing_key: out.public_key.to_vec(),
                    wire,
                });
                Ok::<_, AppError>((r.id, out.signature, Some((out.payload, out.canonical_hash))))
            })
            .collect::<Result<_, _>>()?
    } else {
        // No active signing key (edge case: user was created before
        // signing was introduced, or a previous delete attempt already
        // deactivated the key). Fall back to an empty signature — the
        // retracted_at timestamp alone is still meaningful. With no
        // canonical bytes, there is nothing to dual-write into
        // `signed_objects` either.
        posts_to_retract
            .into_iter()
            .map(|r| (r.id, Vec::new(), None))
            .collect()
    };

    // 1. Retract every still-visible post. One UPDATE per post keeps the
    //    statement simple; the N is bounded by how many posts one user
    //    can make in an account lifetime, which is fine for an
    //    interactive delete.
    for (post_id, sig, signed_bytes) in &retractions {
        sqlx::query!(
            "UPDATE posts SET retracted_at = ?, retraction_signature = ? WHERE id = ?",
            retracted_at,
            sig,
            post_id,
        )
        .execute(&mut **tx)
        .await?;

        sqlx::query!(
            "UPDATE post_revisions SET body = '' WHERE post_id = ?",
            post_id,
        )
        .execute(&mut **tx)
        .await?;

        // Dual-write the canonical retraction bytes into `signed_objects`
        // alongside the projection updates.
        if let Some((payload, canonical_hash)) = signed_bytes {
            crate::signing::store_signed_object(&mut **tx, "retract", payload, sig, canonical_hash)
                .await?;
        }

        // Per-post erasure: the retract is an erasure authority over
        // the post's signed revisions. NULL the canonical payload bytes
        // of every prior `post-rev` for this post; the retract itself
        // is retained. This is the same erasure step that
        // `posts::retract_post` performs on a single-post retract —
        // bulk-delete just runs it per post.
        // Authority is the per-post retract canonical hash (when we
        // have one). `None` falls through to a NULL `erased_by`, which
        // the 410-Gone path treats as "erased without local authority".
        let authority = signed_bytes.as_ref().map(|(_, h)| h);
        crate::signing::erase_post_rev_payloads(&mut **tx, post_id, authority).await?;
    }

    // 1a. Sign + dual-write the umbrella `deactivate` authority once
    //     all per-post retracts are persisted (federation-protocol §10
    //     / signed-payload-format.md §5.11). The deactivate is the
    //     account-wide erasure authority; the retracts above are the
    //     per-post evidence chain. Both share `created_at_ms` so the
    //     §5.11 ordering rule ("deactivate.created_at >= every prior
    //     object by this user") holds at the millisecond. Skip
    //     entirely when the user has no active signing key — there is
    //     no key to sign with, and no peer would accept the resulting
    //     unsigned bytes anyway.
    // Captures the umbrella deactivate's canonical_hash so the
    // subsequent §10.5.3 erasure passes (trust-edges / profile rows in
    // step 6 / 6a) can record it as `erased_by`. `None` when the user
    // has no active signing key — erased_by stays NULL for that case.
    let deactivate_hash: Option<[u8; 32]> = if let Some(key) = signing_key.as_ref() {
        let signed_deactivate = crate::signing::sign_deactivation_with_key(key, created_at_ms);
        crate::signing::store_signed_object(
            &mut **tx,
            "deactivate",
            &signed_deactivate.payload,
            &signed_deactivate.signature,
            &signed_deactivate.canonical_hash,
        )
        .await?;
        // Append the umbrella deactivate to the fanout queue. Routing
        // key is the user's own pubkey (= signer = subject per §7.4).
        let wire = crate::federation::envelope::encode_signed_object(
            &signed_deactivate.payload,
            &signed_deactivate.signature,
        );
        fanout_items.push(FanoutItem {
            canonical_hash: signed_deactivate.canonical_hash,
            routing_key: signed_deactivate.public_key.to_vec(),
            wire,
        });
        Some(signed_deactivate.canonical_hash)
    } else {
        None
    };

    // 1b. Belt-and-suspenders FTS cleanup. The retraction triggers
    //     `posts_fts_after_retract` and `threads_fts_op_after_retract`
    //     (see `migrations/20260506234657_create_fts_tables.sql`)
    //     already handle the common case as step 1's UPDATEs run, but
    //     contentless FTS5 tables retain indexed text independent of
    //     the underlying rows, so any drift between the trigger set
    //     and the data would silently leak the deleted user's content
    //     through `/search`. Spec: `docs/search.md` §GDPR.
    //
    //     posts_fts: drop every row keyed by a post the user authored,
    //     including previously-retracted ones whose FTS row should
    //     already be gone.
    sqlx::query!(
        "DELETE FROM posts_fts WHERE rowid IN \
         (SELECT rowid FROM posts WHERE author = ?)",
        user_id,
    )
    .execute(&mut **tx)
    .await?;

    //     threads_fts: blank op_body on every thread the user authored.
    //     Titles are kept (mirrors the underlying `threads.title`
    //     which we don't blank either — threads are conversation
    //     anchors that other users' replies refer to).
    sqlx::query!(
        "UPDATE threads_fts SET op_body = '' WHERE rowid IN \
         (SELECT rowid FROM threads WHERE author = ?)",
        user_id,
    )
    .execute(&mut **tx)
    .await?;

    // 1c. Attachment cleanup (`docs/attachments.md` §7).
    //
    //     The retraction loop in step 1 already dropped every
    //     `post_attachments` row the user authored (via the
    //     `post_revisions` cascade or via the explicit DELETE inside
    //     `retract_post`), which fires the refcount-dec trigger and
    //     leaves orphan blobs with `refcount = 0`. Three things remain:
    //
    //     a. Sweep the user's staged-but-unbound uploads, then GC any
    //        orphan blob that now has neither a binding nor a staging
    //        anchor. The blob GC sweeps *all* orphans, not just this
    //        user's — piggybacking the same pass is cheaper than
    //        filtering by `uploader` and leaves other users' orphans
    //        to the hourly sweeper anyway.
    sqlx::query!("DELETE FROM attachment_staging WHERE uploader = ?", user_id)
        .execute(&mut **tx)
        .await?;

    //        Run the shared §5 orphan-blob GC predicate. Same function
    //        used by `edit_post` / `retract_post` and by the background
    //        sweeper, so this path cannot drift from the others.
    crate::attachments::gc_orphan_blobs(tx).await?;

    //     b. NULL `uploader` on every surviving blob the user uploaded.
    //        A blob survives the GC above when another user
    //        independently uploaded the same SHA-256 and bound it to a
    //        still-live post (refcount > 0). In that case the row
    //        stays, but its `uploader` column still names the deleted
    //        user — personal data linking them to having uploaded
    //        these bytes. NULLing severs the link; the content lives
    //        on anonymously as content-addressed bytes.
    sqlx::query!(
        "UPDATE attachment_blobs SET uploader = NULL WHERE uploader = ?",
        user_id,
    )
    .execute(&mut **tx)
    .await?;

    //     c. Drop the user's storage-budget row. `lifetime_spent` and
    //        `available_bytes` are account-scoped state with nothing
    //        to associate with once the account is anonymized.
    sqlx::query!(
        "DELETE FROM user_storage_budgets WHERE user_id = ?",
        user_id,
    )
    .execute(&mut **tx)
    .await?;

    // 2. Anonymise the user row. We keep the row (FKs from rooms,
    //    threads, posts, reports, admin_log all reference users.id) but
    //    null out personal fields and stamp deleted_at. The
    //    `deleted_at IS NULL` guard makes this idempotent: a replay of
    //    the delete (e.g. after a crash between commits) won't
    //    overwrite the tombstone with a fresh anonymised name.
    //    `status` and `suspended_until` are cleared so the user row
    //    looks neutral post-deletion — moderation state on a dead
    //    account has no meaning and would only be noise in audit
    //    tooling.
    sqlx::query!(
        "UPDATE users SET display_name = ?, display_name_skeleton = ?, bio = NULL, \
         deleted_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), can_invite = 0, \
         status = 'active', suspended_until = NULL \
         WHERE id = ? AND deleted_at IS NULL",
        anon_name,
        anon_skeleton,
        user_id,
    )
    .execute(&mut **tx)
    .await?;

    // 3. Drop credentials so passkey login is no longer possible.
    sqlx::query!("DELETE FROM credentials WHERE user_id = ?", user_id)
        .execute(&mut **tx)
        .await?;

    // 4. Drop all sessions (including the caller's current session).
    sqlx::query!("DELETE FROM sessions WHERE user_id = ?", user_id)
        .execute(&mut **tx)
        .await?;

    // 5. Drop per-user settings.
    sqlx::query!("DELETE FROM user_settings WHERE user_id = ?", user_id)
        .execute(&mut **tx)
        .await?;

    // 6. Drop every trust edge touching the user — both directions.
    //    Outbound: the deleted user's trust signal stops flowing to
    //    anyone else. Inbound: other users' standing endorsements of
    //    this account have nothing left to weigh (the account can't
    //    authenticate, can't post, and its existing posts are all
    //    retracted), so keeping them around would just mean latent
    //    noise in the trust graph with no behaviour to vouch for.
    //
    //    Erasure first: a self-delete is an account-wide erasure
    //    authority over everything the user signed. We emit no
    //    `deactivate` wire object yet, but the local payload-NULLing
    //    effect is unconditional. NULL the canonical payload bytes
    //    of every trust-edge the user authored *before* dropping the
    //    projection rows — once the rows are gone, the canonical_hash
    //    subquery has nothing to match against. Outbound only; inbound
    //    edges were signed by *other* users and are not ours to erase.
    //    Peers mirror this erasure via the `deactivate` object signed
    //    in step 1a above.
    crate::signing::erase_user_trust_edge_payloads(&mut **tx, user_id, deactivate_hash.as_ref())
        .await?;

    sqlx::query!(
        "DELETE FROM trust_edges WHERE source_user = ? OR target_user = ?",
        user_id,
        user_id,
    )
    .execute(&mut **tx)
    .await?;

    // 6a. Erase canonical bytes of signed `profile` revisions, then
    //     drop the projection rows. Same ordering rationale as step
    //     6 — once the projection is gone the canonical_hash subquery
    //     in `erase_user_profile_revision_payloads` has nothing to
    //     join against. The display_name and bio snapshots in
    //     `profile_revisions` are personal data, so erasure here is
    //     load-bearing for GDPR (the `users` row's display_name /
    //     bio are already anonymised by step 2).
    //     Peers mirror this erasure via the `deactivate` object signed
    //     in step 1a above.
    crate::signing::erase_user_profile_revision_payloads(
        &mut **tx,
        user_id,
        deactivate_hash.as_ref(),
    )
    .await?;

    sqlx::query!("DELETE FROM profile_revisions WHERE user_id = ?", user_id)
        .execute(&mut **tx)
        .await?;

    // 6b. Drop ban/suspend trust snapshots that reference the deleted
    //     user in either capacity. As a `target_user`: self-delete
    //     wipes the moderation-audit history of any past ban/suspend
    //     on the account — consistent with dropping the credentials
    //     and sessions that anchored that identity. As a
    //     `trusting_user`: the snapshot recorded that this user was
    //     endorsing someone at the moment of their ban, but with the
    //     account gone the entry has no one to flag and only serves
    //     to pollute the ban-adjacent watchlist with ghost rows.
    //     (Watchlist queries already filter deleted users, so this is
    //     belt-and-suspenders for any future consumer of the table.)
    sqlx::query!(
        "DELETE FROM ban_trust_snapshots WHERE target_user = ? OR trusting_user = ?",
        user_id,
        user_id,
    )
    .execute(&mut **tx)
    .await?;

    // 7. Drop any in-flight WebAuthn challenges tied to the user.
    sqlx::query!("DELETE FROM auth_challenges WHERE user_id = ?", user_id)
        .execute(&mut **tx)
        .await?;

    // 7b. Drop per-user room favorites. The FK has ON DELETE CASCADE on
    //     users.id, but this soft-delete only anonymises the users row
    //     (the row stays for FK integrity with rooms/threads/posts), so
    //     the cascade never fires. Delete explicitly.
    sqlx::query!("DELETE FROM room_favorites WHERE user_id = ?", user_id)
        .execute(&mut **tx)
        .await?;

    // 7c. Drop user_tags in both directions. Same cascade caveat as 7b:
    //     ON DELETE CASCADE on users.id never fires because we don't
    //     actually delete the row. Outbound (`viewer_id`): the deleted
    //     user's private tag list is personal data and goes with the
    //     account. Inbound (`target_id`): other users' tags pointing at
    //     this account would still resolve to a `[deleted]` placeholder
    //     forever — drop them so a recycled username (after the row
    //     itself is eventually purged) can't surface someone else's
    //     stale label.
    sqlx::query!(
        "DELETE FROM user_tags WHERE viewer_id = ? OR target_id = ?",
        user_id,
        user_id,
    )
    .execute(&mut **tx)
    .await?;

    // 8. Revoke any open invites the user created so nobody else can
    //    sign up against the deleted account.
    sqlx::query!(
        "UPDATE invites SET revoked_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE created_by = ? AND revoked_at IS NULL",
        user_id,
    )
    .execute(&mut **tx)
    .await?;

    // 9. Deactivate signing keys rather than deleting them. Existing
    //    post-revision signatures remain verifiable against the public
    //    half, so content accountability is preserved.
    sqlx::query!(
        "UPDATE signing_keys SET active = 0 WHERE user_id = ?",
        user_id
    )
    .execute(&mut **tx)
    .await?;

    // 10. Federation per-key migration / registration state.
    //     `user_homes`, `user_moves`, and `registration_challenges` are
    //     keyed on the user's raw 32-byte public key (not `users.id`),
    //     so they're invisible to every FK cascade above. Fetch the
    //     pubkey from the users row to drive the targeted deletes.
    //     `fetch_optional` rather than `fetch_one` so a row that's
    //     already been anonymised (step 2 ran but a crash skipped step
    //     10) replays cleanly — the deletes degrade to no-ops.
    let pubkey_row = sqlx::query!("SELECT public_key FROM users WHERE id = ?", user_id,)
        .fetch_optional(&mut **tx)
        .await?;

    if let Some(row) = pubkey_row {
        let user_key: &[u8] = row.public_key.as_slice();

        // 10a. Drop the §12.4 resolved-current-home projection row.
        //      The row tells peers "for this pubkey, the current
        //      authoritative home is X"; with the account erased the
        //      pubkey no longer denotes a live identity here. Dropping
        //      the projection causes the local "resolved current home"
        //      cache to fall back to the bare `users.public_key`
        //      lookup, which for a self-deleted local user will not
        //      match (the anonymised row's public_key is unchanged but
        //      the account has been deactivated via §10 deactivate).
        sqlx::query!("DELETE FROM user_homes WHERE user_key = ?", user_key,)
            .execute(&mut **tx)
            .await?;

        // 10b. Drop any in-flight §13.1 registration challenges this
        //      pubkey was issued. Almost always empty (the ceremony
        //      either consumes the nonce within minutes or the
        //      `session::cleanup_loop` sweep GCs it within the hour),
        //      but explicit cleanup keeps the GDPR delete free of
        //      personal data linkage to the deleted key.
        sqlx::query!(
            "DELETE FROM registration_challenges WHERE user_key = ?",
            user_key,
        )
        .execute(&mut **tx)
        .await?;

        // 10c. `user_moves` is intentionally NOT dropped here. Per
        //      protocol §12.5, the move chain for a key is retained
        //      indefinitely so peers walking §12.3 backfill see the
        //      complete history even after the originating account
        //      has been erased. The rows hold only canonical_hash +
        //      timestamps (no personal data beyond the pubkey itself,
        //      which is the chain identifier and must remain
        //      referenceable for the chain to verify). The canonical
        //      payload bytes already in `signed_objects` are signed
        //      move declarations the user authored — the same
        //      "accountability is preserved" rationale that keeps
        //      signing-key publics around (step 9) applies here.
    }

    Ok(DeactivationFanout {
        items: fanout_items,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Consistent base64url (no padding) encoder, matching the convention
/// used elsewhere in the server (`session::generate_token`, invite codes).
fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
