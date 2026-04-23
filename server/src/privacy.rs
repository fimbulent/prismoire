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
//! # Delete (`DELETE /api/me`)
//!
//! Soft-deletes the user:
//!
//! - Retracts every non-retracted post (one signed retraction per post,
//!   bodies nulled — same shape as `posts::retract_post`).
//! - Anonymises the `users` row: display_name becomes `deleted-<hex>`,
//!   bio nulled, `deleted_at` set, `can_invite = 0`.
//! - Drops credentials, sessions, user_settings, auth_challenges, and
//!   *all* trust_edges touching the user (both outbound and inbound).
//!   Outbound edges stop flowing the deleted user's trust signal
//!   through the graph; inbound edges are dropped too because the
//!   deleted user can no longer author content, so a standing trust
//!   endorsement of them has nothing to weigh anymore and would only
//!   serve as latent noise in the trust graph.
//! - Drops `ban_trust_snapshots` rows referencing the user in either
//!   capacity (target of a past ban/suspend, or a truster captured at
//!   the moment someone else was moderated). Same rationale: with the
//!   account gone, those snapshot rows have nothing to describe.
//! - Revokes any open invites the user created.
//! - Deactivates signing keys (`active = 0`) rather than deleting them, so
//!   past signatures on content still authored by other users remain
//!   verifiable.
//!
//! The row itself stays for FK integrity — rooms, threads, posts, reports,
//! and admin_log all reference `users.id`. The `deleted_at` tombstone is
//! what gates UI rendering ("[deleted]") and login attempts downstream.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use uuid::Uuid;

use crate::display_name::display_name_skeleton;
use crate::error::{AppError, ErrorCode};
use crate::session::{RestrictedAuthUser, clear_session_cookie};
use crate::state::AppState;

/// Wire version of the export payload. Bump whenever the shape changes so
/// downstream tools can branch on it.
const EXPORT_VERSION: u32 = 1;

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
    pub invites_created: Vec<InviteExport>,
    pub threads: Vec<ThreadExport>,
    pub posts: Vec<PostExport>,
    pub reports_filed: Vec<ReportExport>,
    pub moderation_actions_against_me: Vec<AdminLogExport>,
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
}

#[derive(Serialize)]
pub struct SettingsExport {
    pub theme: String,
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
    /// Ed25519 public key, base64url (no padding).
    pub public_key_b64: String,
    /// Ed25519 private key, base64url (no padding). Sensitive — treat the
    /// export file as you would a private key on disk.
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
}

#[derive(Serialize)]
pub struct PostRevisionExport {
    pub revision: i64,
    pub body: String,
    /// Ed25519 signature over the revision body, base64url (no padding).
    pub signature_b64: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct PostExport {
    pub id: String,
    pub thread_id: String,
    pub parent_id: Option<String>,
    pub created_at: String,
    pub retracted_at: Option<String>,
    pub revisions: Vec<PostRevisionExport>,
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
           can_invite AS "can_invite!: bool", suspended_until, deleted_at
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

    let theme = sqlx::query!(
        r#"SELECT COALESCE((SELECT theme FROM user_settings WHERE user_id = ?), 'rose-pine') AS "theme!: String""#,
        user_id,
    )
    .fetch_one(db)
    .await?
    .theme;

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
        r#"SELECT id, public_key, private_key, created_at, active AS "active!: bool"
         FROM signing_keys WHERE user_id = ? ORDER BY created_at ASC"#,
        user_id,
    )
    .fetch_all(db)
    .await?;

    let signing_keys: Vec<SigningKeyExport> = signing_key_rows
        .into_iter()
        .map(|r| SigningKeyExport {
            id: r.id,
            public_key_b64: b64(&r.public_key),
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
        r#"SELECT t.id, t.title, r.slug, t.created_at, t.locked AS "locked!: bool", t.reply_count
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
        })
        .collect();

    let post_rows = sqlx::query!(
        "SELECT id, thread, parent, created_at, retracted_at \
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

        let revisions = revision_rows
            .into_iter()
            .map(|r| PostRevisionExport {
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
        },
        settings: SettingsExport { theme },
        credentials,
        signing_keys,
        trust_edges_outbound,
        invites_created,
        threads,
        posts,
        reports_filed,
        moderation_actions_against_me,
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
    soft_delete_user(&mut tx, &user.user_id).await?;
    tx.commit().await?;

    // Trust graph drops the deleted user's outbound edges on the next
    // rebuild.
    state.trust_graph_notify.notify_one();

    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, clear_session_cookie().parse().unwrap());

    Ok((StatusCode::NO_CONTENT, headers))
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
/// Does **not** notify the trust graph or touch any session cookie —
/// those concerns are handled by the calling endpoint, which has the
/// request context (`AppState`, `HeaderMap`) that this helper doesn't
/// want to depend on.
pub(crate) async fn soft_delete_user(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: &str,
) -> Result<(), AppError> {
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
                eprintln!(
                    "privacy::soft_delete_user: signing key for user {user_id} has invalid length {} (expected 32)",
                    v.len()
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

    // Pre-compute retraction signatures in memory so the subsequent
    // UPDATEs are pure DB work (signing is CPU-only and does not touch
    // the pool, so doing it inside the tx is fine).
    let retractions: Vec<(String, Vec<u8>)> = if let Some(key) = signing_key.as_ref() {
        posts_to_retract
            .into_iter()
            .map(|r| {
                let msg = format!("retract:{}", r.id);
                let sig = key.sign(msg.as_bytes()).to_bytes().to_vec();
                (r.id, sig)
            })
            .collect()
    } else {
        // No active signing key (edge case: user was created before
        // signing was introduced, or a previous delete attempt already
        // deactivated the key). Fall back to an empty signature — the
        // retracted_at timestamp alone is still meaningful.
        posts_to_retract
            .into_iter()
            .map(|r| (r.id, Vec::new()))
            .collect()
    };

    // 1. Retract every still-visible post. One UPDATE per post keeps the
    //    statement simple; the N is bounded by how many posts one user
    //    can make in an account lifetime, which is fine for an
    //    interactive delete.
    for (post_id, sig) in &retractions {
        sqlx::query!(
            "UPDATE posts SET retracted_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), \
             retraction_signature = ? WHERE id = ?",
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
    }

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
    sqlx::query!(
        "DELETE FROM trust_edges WHERE source_user = ? OR target_user = ?",
        user_id,
        user_id,
    )
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

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Consistent base64url (no padding) encoder, matching the convention
/// used elsewhere in the server (`session::generate_token`, invite codes).
fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
