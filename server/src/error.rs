//! Structured API error contract.
//!
//! Handlers return `Result<T, AppError>`. `AppError` carries a stable
//! machine-readable [`ErrorCode`] plus the HTTP status it should
//! serialize as. Internal errors (database failures, serialization
//! problems, webauthn library errors) are logged server-side with a
//! correlation id and mapped to [`ErrorCode::Internal`] — their raw
//! details never escape to the wire.
//!
//! The JSON wire format is:
//!
//! ```json
//! { "error": "<legacy message>", "code": "<snake_case_code>", "fields": { ... } }
//! ```
//!
//! The `error` field is a legacy free-form string kept for one release
//! so older frontends can still render *something*. New clients MUST
//! read `code` (and `fields` for per-field validation). See
//! `docs/fix-errors.md`.

use std::collections::HashMap;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use uuid::Uuid;

/// JSON envelope serialized on every non-2xx response.
///
/// `error` is a legacy human-readable string preserved for one release
/// cycle so the frontend can migrate without breakage. New code should
/// branch on `code` (and `fields` when a per-field mapping is useful).
#[derive(Debug, Serialize)]
pub struct ApiError {
    /// Legacy free-form message. Safe to show a user as a last-resort
    /// fallback, but new code should use `code` + a client-side
    /// message catalog. Will be dropped once all clients are migrated.
    pub error: String,
    /// Stable snake_case machine-readable code. The frontend maps
    /// this to a localized user-facing string via
    /// `web/src/lib/i18n/errors.ts`.
    pub code: ErrorCode,
    /// Optional per-field error map for form validation. Keys are
    /// field names ("display_name", "bio", etc.); values are per-field
    /// error codes. Omitted from the wire payload when empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<HashMap<String, ErrorCode>>,
}

/// Stable, machine-readable error code set. Every variant is part of
/// the public API contract between the Rust server and the SvelteKit
/// frontend — renaming or removing a variant is a breaking change.
///
/// Variants serialize as snake_case strings matching the TypeScript
/// `ErrorCode` union in `web/src/lib/api/auth.ts`.
///
/// `#[allow(dead_code)]` keeps `BadRequest` on the enum: it's a
/// documented catch-all that handlers can reach for when no more
/// specific code applies, and the frontend catalog relies on it as
/// the generic 4xx fallback. Every other variant has a live call
/// site (including `RateLimited`, which is produced by
/// `rate_limit::govern_error_handler` when the tower_governor
/// middleware rejects a request).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    // -- Auth / session ----------------------------------------------
    /// The current request requires authentication.
    Unauthenticated,
    /// The caller is authenticated but not allowed to perform this action.
    Forbidden,
    /// Auth challenge was missing, expired, or did not match a known ceremony.
    InvalidChallenge,
    /// WebAuthn passkey registration or authentication failed.
    PasskeyCeremonyFailed,
    /// No user row matched the provided display name.
    UserNotFound,
    /// The user has no credentials registered (can happen after passkey removal).
    NoCredentials,
    /// Requested display name is malformed (empty, too long, mixed-script, etc).
    InvalidDisplayName,
    /// Requested display name collides with an existing account.
    DisplayNameTaken,
    /// Content signature check failed.
    InvalidSignature,
    /// Profile edits are restricted to the profile's owner.
    NotOwnProfile,

    // -- Invites -----------------------------------------------------
    /// No invite row matched the provided code / id.
    InviteNotFound,
    /// Invite code past its `expires_at`.
    InviteExpired,
    /// Invite code is structurally invalid or does not match any row.
    InviteInvalid,
    /// Invite reached its `max_uses` cap.
    InviteExhausted,
    /// Signup requires an invite code and none was provided.
    InviteRequired,
    /// `max_uses` field below minimum (< 1).
    InviteMaxUsesInvalid,
    /// User's invite privileges have been revoked by an admin.
    InvitePrivilegeRevoked,
    /// `expires_in_seconds` field outside allowed range.
    InviteExpiryInvalid,

    // -- Setup -------------------------------------------------------
    /// Instance setup has already been completed; endpoint is now gated.
    SetupAlreadyComplete,
    /// Setup token provided by the client did not match the server-side value.
    SetupTokenInvalid,
    /// Server does not have a setup token configured (misconfiguration).
    SetupTokenMissing,

    // -- Rooms -------------------------------------------------------
    /// No room row matched the provided id / slug.
    RoomNotFound,
    /// Room slug failed validation (length, characters, etc).
    InvalidRoomSlug,
    /// Only admins can post threads in the announcements room.
    AnnouncementsAdminOnly,

    // -- Threads -----------------------------------------------------
    /// No thread row matched the provided id.
    ThreadNotFound,
    /// Thread is locked and cannot accept new replies.
    ThreadLocked,
    /// Admin lock: thread is already locked.
    ThreadAlreadyLocked,
    /// Admin unlock: thread is not currently locked.
    ThreadNotLocked,
    /// Pagination cursor could not be parsed.
    InvalidCursor,
    /// Unknown / unsupported sort mode in a pagination cursor.
    InvalidSortMode,
    /// `seen_ids` array exceeded the per-request cap.
    SeenIdsExceeded,

    // -- Posts -------------------------------------------------------
    /// No post row matched the provided id.
    PostNotFound,
    /// Post body failed validation (empty, too long, etc).
    InvalidPostBody,
    /// Link-post URL failed validation (bad scheme, missing host,
    /// userinfo, etc).
    InvalidPostLink,
    /// Thread title failed validation (empty, too long, etc).
    InvalidThreadTitle,
    /// Cannot edit a retracted post.
    PostRetracted,
    /// Admin retract: post is already retracted.
    PostAlreadyRetracted,
    /// Only the post's author can perform this action.
    NotPostAuthor,
    /// Reply's parent post does not belong to the current thread.
    ParentThreadMismatch,
    /// Cannot reply to a retracted post.
    ParentRetracted,

    // -- Trust edges -------------------------------------------------
    /// Cannot create a trust edge from a user to themselves.
    SelfTrustEdge,
    /// No existing trust edge to remove.
    NoTrustEdge,
    /// Trust-list direction parameter was neither "trusts" nor "trusted_by".
    InvalidTrustDirection,
    /// A pasted trust code (§11.9.5) was malformed or failed validation.
    InvalidTrustCode,

    // -- User tags ---------------------------------------------------
    /// Cannot tag yourself.
    SelfTag,
    /// Tag exceeds the configured maximum length (in grapheme clusters).
    TagTooLong,

    // -- Misc user fields --------------------------------------------
    /// Bio exceeds the configured maximum length.
    BioTooLong,

    // -- Admin -------------------------------------------------------
    /// Action requires admin privileges.
    AdminRequired,
    /// Admin action requires a non-empty `reason`.
    ReasonRequired,
    /// Admin action `reason` exceeds the per-field length cap.
    ReasonTooLong,
    /// Target user is already banned.
    AlreadyBanned,
    /// Target user is not currently banned.
    NotBanned,
    /// Target user is already suspended.
    AlreadySuspended,
    /// Target user is not currently suspended.
    NotSuspended,
    /// Cannot ban or suspend an admin.
    CannotModerateAdmin,
    /// Moderation target (user or thread) is homed on another instance;
    /// only its home instance may issue authoritative moderation status.
    RemoteModerationTarget,
    /// Invalid suspension duration.
    InvalidDuration,
    /// User's invite privileges are already in the requested state.
    InvitePrivilegeUnchanged,
    /// Admin delete: target user has already been deleted.
    UserAlreadyDeleted,
    /// Admin delete: target room has already been deleted.
    RoomAlreadyDeleted,
    /// Admin delete: the confirmation value submitted with the form
    /// (display name for users, slug for rooms) did not match the
    /// target's current value. Guards against mis-click deletions.
    ConfirmationMismatch,

    // -- Reports -----------------------------------------------------
    /// Report reason is not one of the accepted enum values.
    ReportReasonInvalid,
    /// Report `detail` exceeds [`MAX_REPORT_DETAIL_LEN`](crate::signed::MAX_REPORT_DETAIL_LEN).
    ReportDetailTooLong,
    /// The user has already reported this post.
    AlreadyReported,
    /// No report row matched the provided id.
    ReportNotFound,
    /// Users cannot report their own posts.
    SelfReport,

    // -- Settings ----------------------------------------------------
    /// Theme identifier is not in the allowed set.
    InvalidTheme,
    /// Prose font identifier is not in the allowed set.
    InvalidFont,

    // -- Favorites ---------------------------------------------------
    /// User already has the maximum number of favorite rooms.
    FavoriteCapExceeded,
    /// Reorder payload's room set did not match the user's current
    /// favorites — the client's view is stale and must refetch.
    FavoriteSetMismatch,

    // -- Attachments -------------------------------------------------
    /// No attachment blob row matched the requested hash, or the hash is
    /// not visible to the requester. The two are deliberately fused on
    /// the wire so visibility does not leak via response shape
    /// (`docs/attachments.md` §4 step 2).
    AttachmentNotFound,
    /// Upload exceeded the per-blob byte cap (input or post-re-encode
    /// stored size).
    AttachmentTooLarge,
    /// Upload's detected MIME is not in [`signed::ALLOWED_MIMES`]
    /// (`docs/attachments.md` §3 step 2).
    AttachmentMimeRejected,
    /// Image dimensions exceeded `MAX_IMAGE_PX_DECODE`.
    AttachmentImageDimensions,
    /// Image bytes failed to decode under the declared MIME.
    AttachmentImageDecode,
    /// Multipart request was malformed, missing the `file` part, or
    /// carried multiple parts.
    AttachmentMultipartInvalid,
    /// Upload would overdraw the user's storage budget.
    BudgetExceeded,
    /// Filename failed the `FILENAME_RULES` sanitization (§2.2):
    /// empty after sanitization, or did not round-trip the
    /// canonicalization pass.
    AttachmentFilenameInvalid,
    /// Two `attachments[]` entries share the same `content_hash`.
    AttachmentDuplicateHash,
    /// Two `attachments[]` entries share the same (canonicalized)
    /// `filename`. Body `![](filename)` references resolve by name, so
    /// duplicate names would be ambiguous — bind-time rejection keeps
    /// the resolution rule deterministic (`docs/attachments.md` §3).
    AttachmentDuplicateFilename,
    /// A body `![](filename)` reference appeared more than once. Each
    /// attachment may be inlined at most once per revision.
    AttachmentInlineRefDuplicate,
    /// A body `![](filename)` reference resolved to a non-image MIME.
    /// Only image attachments can be inlined; other MIMEs must render
    /// as a download chip below the post.
    AttachmentInlineRefNotImage,
    /// Upload was zero bytes (no content to share).
    AttachmentEmpty,

    // -- Federation (operator peering) -------------------------------
    /// Operator tried to peer with this instance itself (the fetched
    /// identity's pubkey matched our own signing key).
    SelfPeering,
    /// Another peer row already binds the target domain to a different
    /// instance pubkey.
    PeerDomainConflict,
    /// The supplied / fetched instance domain failed structural
    /// validation (SSRF boundary).
    InvalidPeerDomain,
    /// Could not reach the target instance to fetch its identity or
    /// deliver a handshake message.
    PeerUnreachable,
    /// The target instance was reachable but rejected the handshake
    /// (non-2xx peering response).
    PeerHandshakeFailed,
    /// The target instance returned a malformed or unparseable
    /// identity card.
    PeerIdentityInvalid,
    /// No peer row matched the supplied instance pubkey.
    PeerNotFound,

    // -- Catch-all ---------------------------------------------------
    /// Generic client error when no more specific code applies.
    BadRequest,
    /// Server-side rate limiter rejected the request.
    RateLimited,
    /// Unclassified server-side failure. Logged with a correlation id
    /// server-side; the wire payload carries no further detail.
    Internal,
}

impl ErrorCode {
    /// HTTP status the error should serialize with.
    ///
    /// Kept as a method (rather than stored on each variant) so adding
    /// a new code is a one-line change in both `status()` and
    /// `legacy_message()`.
    pub fn status(self) -> StatusCode {
        match self {
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden
            | Self::AdminRequired
            | Self::NotOwnProfile
            | Self::NotPostAuthor
            | Self::AnnouncementsAdminOnly
            | Self::CannotModerateAdmin
            | Self::RemoteModerationTarget
            | Self::InvitePrivilegeRevoked => StatusCode::FORBIDDEN,

            Self::UserNotFound
            | Self::NoCredentials
            | Self::InviteNotFound
            | Self::RoomNotFound
            | Self::ThreadNotFound
            | Self::PostNotFound
            | Self::NoTrustEdge
            | Self::ReportNotFound
            | Self::AttachmentNotFound => StatusCode::NOT_FOUND,

            Self::DisplayNameTaken
            | Self::SetupAlreadyComplete
            | Self::ThreadAlreadyLocked
            | Self::PostAlreadyRetracted
            | Self::AlreadyReported
            | Self::AlreadyBanned
            | Self::AlreadySuspended
            | Self::NotBanned
            | Self::NotSuspended
            | Self::InvitePrivilegeUnchanged
            | Self::UserAlreadyDeleted
            | Self::RoomAlreadyDeleted
            | Self::FavoriteSetMismatch
            | Self::PeerDomainConflict
            | Self::FavoriteCapExceeded => StatusCode::CONFLICT,

            Self::PeerNotFound => StatusCode::NOT_FOUND,

            Self::PeerUnreachable | Self::PeerHandshakeFailed | Self::PeerIdentityInvalid => {
                StatusCode::BAD_GATEWAY
            }

            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,

            Self::AttachmentTooLarge | Self::AttachmentImageDimensions => {
                StatusCode::PAYLOAD_TOO_LARGE
            }
            Self::AttachmentMimeRejected => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::BudgetExceeded => StatusCode::PAYMENT_REQUIRED,

            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,

            // Everything else is 400.
            Self::InvalidChallenge
            | Self::PasskeyCeremonyFailed
            | Self::InvalidDisplayName
            | Self::InvalidSignature
            | Self::InviteExpired
            | Self::InviteInvalid
            | Self::InviteExhausted
            | Self::InviteRequired
            | Self::InviteMaxUsesInvalid
            | Self::InviteExpiryInvalid
            | Self::SetupTokenInvalid
            | Self::SetupTokenMissing
            | Self::InvalidRoomSlug
            | Self::ThreadLocked
            | Self::ThreadNotLocked
            | Self::InvalidCursor
            | Self::InvalidSortMode
            | Self::SeenIdsExceeded
            | Self::InvalidPostBody
            | Self::InvalidPostLink
            | Self::InvalidThreadTitle
            | Self::PostRetracted
            | Self::ParentThreadMismatch
            | Self::ParentRetracted
            | Self::SelfTrustEdge
            | Self::InvalidTrustDirection
            | Self::InvalidTrustCode
            | Self::SelfTag
            | Self::TagTooLong
            | Self::BioTooLong
            | Self::ReasonRequired
            | Self::ReasonTooLong
            | Self::ReportReasonInvalid
            | Self::ReportDetailTooLong
            | Self::SelfReport
            | Self::InvalidTheme
            | Self::InvalidFont
            | Self::InvalidDuration
            | Self::ConfirmationMismatch
            | Self::AttachmentImageDecode
            | Self::AttachmentMultipartInvalid
            | Self::AttachmentFilenameInvalid
            | Self::AttachmentDuplicateHash
            | Self::AttachmentDuplicateFilename
            | Self::AttachmentInlineRefDuplicate
            | Self::AttachmentInlineRefNotImage
            | Self::AttachmentEmpty
            | Self::SelfPeering
            | Self::InvalidPeerDomain
            | Self::BadRequest => StatusCode::BAD_REQUEST,
        }
    }

    /// Legacy human-readable fallback used only for the dual-written
    /// `error` field on the wire. Dropped once clients stop reading it.
    pub fn legacy_message(self) -> &'static str {
        match self {
            Self::Unauthenticated => "authentication required",
            Self::Forbidden => "forbidden",
            Self::InvalidChallenge => "invalid or expired challenge",
            Self::PasskeyCeremonyFailed => "webauthn ceremony failed",
            Self::UserNotFound => "user not found",
            Self::NoCredentials => "no credentials registered",
            Self::InvalidDisplayName => "display name is invalid",
            Self::DisplayNameTaken => "display name already taken",
            Self::InvalidSignature => "invalid signature",
            Self::NotOwnProfile => "can only edit your own profile",

            Self::InviteNotFound => "invite not found",
            Self::InviteExpired => "invite code has expired",
            Self::InviteInvalid => "invalid invite code",
            Self::InviteExhausted => "invite code has been fully used",
            Self::InviteRequired => "invite code required",
            Self::InviteMaxUsesInvalid => "max_uses must be at least 1",
            Self::InvitePrivilegeRevoked => "invite privileges have been revoked",
            Self::InviteExpiryInvalid => "invite expiry is out of range",

            Self::SetupAlreadyComplete => "setup already completed",
            Self::SetupTokenInvalid => "invalid setup token",
            Self::SetupTokenMissing => "no setup token configured",

            Self::RoomNotFound => "room not found",
            Self::InvalidRoomSlug => "room slug is invalid",
            Self::AnnouncementsAdminOnly => "only admins can post in announcements",

            Self::ThreadNotFound => "thread not found",
            Self::ThreadLocked => "thread is locked",
            Self::ThreadAlreadyLocked => "thread is already locked",
            Self::ThreadNotLocked => "thread is not locked",
            Self::InvalidCursor => "invalid cursor",
            Self::InvalidSortMode => "invalid cursor sort mode",
            Self::SeenIdsExceeded => "seen_ids exceeds maximum",

            Self::PostNotFound => "post not found",
            Self::InvalidPostBody => "post body is invalid",
            Self::InvalidPostLink => "link is invalid",
            Self::InvalidThreadTitle => "thread title is invalid",
            Self::PostRetracted => "cannot edit a retracted post",
            Self::PostAlreadyRetracted => "post is already retracted",
            Self::NotPostAuthor => "you are not the author of this post",
            Self::ParentThreadMismatch => "parent post does not belong to this thread",
            Self::ParentRetracted => "cannot reply to a retracted post",

            Self::SelfTrustEdge => "cannot set trust edge on yourself",
            Self::NoTrustEdge => "no trust edge to remove",
            Self::InvalidTrustDirection => "direction must be 'trusts' or 'trusted_by'",
            Self::InvalidTrustCode => "trust code is malformed or invalid",

            Self::SelfTag => "cannot tag yourself",
            Self::TagTooLong => "tag is too long",

            Self::BioTooLong => "bio is too long",

            Self::AdminRequired => "admin access required",
            Self::ReasonRequired => "reason is required",
            Self::ReasonTooLong => "reason is too long",
            Self::AlreadyBanned => "user is already banned",
            Self::NotBanned => "user is not banned",
            Self::AlreadySuspended => "user is already suspended",
            Self::NotSuspended => "user is not suspended",
            Self::CannotModerateAdmin => "cannot ban or suspend an admin",
            Self::RemoteModerationTarget => "target is homed on another instance",
            Self::InvalidDuration => "invalid suspension duration",
            Self::InvitePrivilegeUnchanged => "invite privileges already in requested state",
            Self::UserAlreadyDeleted => "user is already deleted",
            Self::RoomAlreadyDeleted => "room is already deleted",
            Self::ConfirmationMismatch => "confirmation value did not match",

            Self::ReportReasonInvalid => "invalid report reason",
            Self::ReportDetailTooLong => "report detail is too long",
            Self::AlreadyReported => "you have already reported this post",
            Self::ReportNotFound => "report not found",
            Self::SelfReport => "you cannot report your own post",

            Self::InvalidTheme => "invalid theme",
            Self::InvalidFont => "invalid font",

            Self::FavoriteCapExceeded => "favorite rooms limit reached",
            Self::FavoriteSetMismatch => "favorite rooms changed in another tab; please refetch",

            Self::AttachmentNotFound => "attachment not found",
            Self::AttachmentTooLarge => "attachment exceeds size cap",
            Self::AttachmentMimeRejected => "attachment MIME type is not allowed",
            Self::AttachmentImageDimensions => "image dimensions exceed cap",
            Self::AttachmentImageDecode => "image could not be decoded",
            Self::AttachmentMultipartInvalid => "multipart upload was malformed",
            Self::BudgetExceeded => "storage budget exceeded",
            Self::AttachmentFilenameInvalid => "filename is invalid",
            Self::AttachmentDuplicateHash => "the same attachment was bound twice in this post",
            Self::AttachmentDuplicateFilename => "two attachments cannot share the same filename",
            Self::AttachmentInlineRefDuplicate => {
                "an attachment can only be inlined once in the body"
            }
            Self::AttachmentInlineRefNotImage => {
                "only image attachments can be inlined in the body"
            }
            Self::AttachmentEmpty => "attachment has zero bytes",

            Self::SelfPeering => "cannot peer with this instance itself",
            Self::PeerDomainConflict => "another peer already uses this domain",
            Self::InvalidPeerDomain => "instance domain is invalid",
            Self::PeerUnreachable => "could not reach the instance",
            Self::PeerHandshakeFailed => "the instance rejected the peering request",
            Self::PeerIdentityInvalid => "the instance returned an invalid identity",
            Self::PeerNotFound => "peer not found",

            Self::BadRequest => "bad request",
            Self::RateLimited => "rate limited",
            Self::Internal => "internal server error",
        }
    }
}

/// Handler-facing error type. Converts into a JSON [`ApiError`] response
/// via the `IntoResponse` impl below.
///
/// Prefer the constructors (`AppError::code`, `AppError::with_message`,
/// `AppError::with_fields`) over building the struct directly so future
/// additions (correlation ids, telemetry) can be added in one place.
#[derive(Debug)]
pub struct AppError {
    code: ErrorCode,
    /// Optional override for the legacy `error` string. If `None`, the
    /// default from `ErrorCode::legacy_message()` is used. This lets
    /// validator helpers (which produce richer `"display name must be
    /// at most 32 characters"`-style strings) preserve their original
    /// message in the legacy field while still tagging a stable `code`.
    message: Option<String>,
    fields: Option<HashMap<String, ErrorCode>>,
}

impl AppError {
    /// Construct an error from just a code. The legacy message is the
    /// default for that code.
    pub fn code(code: ErrorCode) -> Self {
        Self {
            code,
            message: None,
            fields: None,
        }
    }

    /// Construct an error with a custom legacy message override. The
    /// message is only used for the dual-written `error` field —
    /// clients on the new contract read the `code` and ignore this
    /// string. Use this sparingly (validators, dynamic length limits).
    pub fn with_message(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: Some(message.into()),
            fields: None,
        }
    }

    /// Attach a per-field error map for form validation feedback.
    ///
    /// Currently unused by handlers — reserved for form endpoints
    /// that need to surface multiple field-level codes in a single
    /// response. `#[allow(dead_code)]` keeps the builder on the public
    /// surface so callers can start using it without a separate edit.
    #[allow(dead_code)]
    pub fn with_fields(mut self, fields: HashMap<String, ErrorCode>) -> Self {
        self.fields = Some(fields);
        self
    }

    /// Read the `ErrorCode` this error will serialize with. Test-only
    /// today — handlers should not branch on the code, only construct
    /// them. The IntoResponse path consumes `self.code` directly.
    #[cfg(test)]
    pub fn error_code(&self) -> ErrorCode {
        self.code
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.code.status();
        let message = self
            .message
            .unwrap_or_else(|| self.code.legacy_message().to_string());
        (
            status,
            Json(ApiError {
                error: message,
                code: self.code,
                fields: self.fields,
            }),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// Automatic conversions from common foreign errors.
// ---------------------------------------------------------------------------
//
// Every conversion below logs the real error server-side with a fresh
// correlation id and maps the wire response to `ErrorCode::Internal`
// (or `PasskeyCeremonyFailed` for webauthn). Raw error details never
// leak to the browser.

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        let id = Uuid::new_v4();
        tracing::error!(error_id = %id, error = %err, "database error");
        AppError::code(ErrorCode::Internal)
    }
}

impl From<webauthn_rs::prelude::WebauthnError> for AppError {
    fn from(err: webauthn_rs::prelude::WebauthnError) -> Self {
        let id = Uuid::new_v4();
        tracing::error!(error_id = %id, error = %err, "webauthn error");
        AppError::code(ErrorCode::PasskeyCeremonyFailed)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        let id = Uuid::new_v4();
        tracing::error!(error_id = %id, error = %err, "serialization error");
        AppError::code(ErrorCode::Internal)
    }
}
