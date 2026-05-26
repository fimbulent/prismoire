//! Layer-2 smoke test: two real Prismoire instances on loopback HTTPS.
//!
//! Pins Task #18's done-when from `docs/federation-impl-plan.md`
//! Phase 5: "two real `cargo run -p prismoire-server` binaries on
//! loopback HTTPS exchange one edge ... if the in-process transport
//! accidentally diverged from reality, this catches it."
//!
//! Interpreted pragmatically: two complete `AppState`s, each behind
//! its own [`axum_server`] TLS listener bound to `127.0.0.1:0`, all
//! within this test process. Every cross-instance call goes through
//! the production [`ReqwestTransport`] over a real TCP socket and a
//! real TLS handshake. The diff against `InProcessTransport`
//! (`tests/common/federation.rs`) is exactly what this test catches:
//! headers the production transport drops, body re-encoding bugs in
//! `reqwest`, envelope-signature bytes that survive `tower::oneshot`
//! but not a round-trip through the network, and so on.
//!
//! Subprocess `cargo run` orchestration would buy us only OS-level
//! process isolation; the failure modes the test is *for* live below
//! that, in the transport seam.
//!
//! ## Why feature-gated
//!
//! Spawns sockets and does a real TLS handshake on every test
//! invocation. Smoke tests live under `tests/smoke/` and are
//! registered as `[[test]]` entries with `required-features =
//! ["smoke-tests"]`, so the default pre-commit run (`cargo test
//! --features test-auth`) does not even compile them. To run the
//! smoke suite explicitly:
//!
//! ```sh
//! cargo test -p prismoire-server --features smoke-tests
//! ```
//!
//! That mirrors the "runnable via a dedicated cargo test invocation,
//! even if not in the default pre-commit set" criterion from the
//! impl plan, and groups all current and future smoke tests under a
//! single feature flag so they can be run or ignored as a unit.
//!
//! ## Crypto provider
//!
//! `axum-server` is configured with `tls-rustls-no-provider`;
//! `reqwest` pulls the *ring* provider through its
//! `rustls-tls-webpki-roots` feature. We install ring as the
//! process-wide default exactly once at the top of each test (the
//! second call is a no-op). That avoids the runtime panic where two
//! providers race to be the default.

#![cfg(feature = "smoke-tests")]

// `tests/common/mod.rs` is shared by every integration test crate;
// because this file lives in a subdirectory, the usual `mod common;`
// lookup would resolve to `tests/smoke/common.rs` (which doesn't
// exist). Point `mod` at the canonical path so smoke tests reuse the
// same harness helpers (`fresh_db`, `test_app_with_pool_transport_and_domain`)
// as the top-level integration tests.
#[path = "../common/mod.rs"]
mod common;

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use prismoire_server::AppState;
use prismoire_server::federation::peering::{
    operator_accept_peer_request, operator_initiate_peer_request,
};
use prismoire_server::federation::transport::{FederationTransport, ReqwestTransport};
use prismoire_server::signed::TrustStance;
use prismoire_server::signing::sign_trust_edge_with_key;
use rand::rngs::OsRng;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use sqlx::SqlitePool;

use common::{fresh_db, test_app_with_pool_transport_and_domain};

// ---------------------------------------------------------------------------
// One-shot crypto / env setup
// ---------------------------------------------------------------------------

/// Install ring as the rustls default crypto provider exactly once
/// per test process. Both `reqwest` (rustls-tls-webpki-roots) and
/// `axum-server` (tls-rustls-no-provider) sample
/// `CryptoProvider::get_default()` lazily; we pre-empt the race so
/// neither side has to install one.
fn install_crypto_provider() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        // `install_default` returns `Err` if a provider has already
        // been installed — that's fine when another test in the same
        // binary beat us to it, so we ignore the result rather than
        // unwrap.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ---------------------------------------------------------------------------
// Per-instance fixture
// ---------------------------------------------------------------------------

/// Everything the test needs to drive one instance from outside: the
/// `AppState` (for DB-level assertions and signing key), the listener
/// address (for the *other* instance to address it by), and an
/// `axum_server::Handle` (for graceful shutdown at the end of the
/// test).
struct SmokeInstance {
    state: Arc<AppState>,
    /// Bound `127.0.0.1:PORT`. `instance_domain` on `state` carries the
    /// same string — held here too so tests that log "A=...; B=..."
    /// when diagnosing a failure don't need to dig the value out of
    /// `state`.
    #[allow(dead_code)]
    addr: SocketAddr,
    handle: axum_server::Handle<SocketAddr>,
}

/// Build one instance: fresh in-memory DB, fresh signing key,
/// `ReqwestTransport` over the shared self-signed-tolerant client,
/// production `build_app` router served via an `axum-server` TLS
/// listener on `127.0.0.1:0`. The bind happens before
/// `AppState` construction so the resulting port can be baked into
/// `instance_domain` — the production transport URL-assembles
/// `https://{instance_domain}{path}`, so the port must round-trip
/// exactly through the peers table.
async fn spawn_smoke_instance(client: reqwest::Client, tls: RustlsConfig) -> SmokeInstance {
    // Step 1: pre-bind so we can pin the port into `instance_domain`.
    // `127.0.0.1:0` lets the OS pick an ephemeral free port. The
    // listener has to be flipped to non-blocking before tokio's
    // runtime will accept it — `std::net::TcpListener` is blocking by
    // default and tokio's reactor outright refuses such fds (since
    // tokio 1.x they panic rather than silently park a worker
    // thread).
    let std_listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral loopback port");
    std_listener
        .set_nonblocking(true)
        .expect("set_nonblocking on loopback listener");
    let addr = std_listener.local_addr().expect("local_addr");
    let instance_domain = format!("{}", addr); // e.g. "127.0.0.1:54321"

    // Step 2: pool + transport. Both `AppState` and `ReqwestTransport`
    // hold the same `SqlitePool` clone — the transport reads
    // `peers.instance_domain` that the handlers wrote on inbound
    // `/peer-request`. The `true` enables the SSRF kill-switch's
    // loopback escape hatch so `127.0.0.1:PORT` peers can be reached;
    // production binaries derive this bool from
    // `PRISMOIRE_FEDERATION_ALLOW_PRIVATE_TARGETS` in `main.rs`.
    let pool: SqlitePool = fresh_db().await;
    let transport: Arc<dyn FederationTransport> =
        Arc::new(ReqwestTransport::new(pool.clone(), client, true));

    // Step 3: assemble the full production router via the shared
    // helper. Skipping the helper would mean re-listing every
    // `AppState` field here and silently drifting when new fields
    // land.
    let (router, state) =
        test_app_with_pool_transport_and_domain(pool, transport, &instance_domain).await;

    // Step 4: spawn the TLS server on the pre-bound listener. The
    // `Handle` is the graceful-shutdown knob; we hand it back so the
    // test fixture can drop it at the end and free the port.
    let handle = axum_server::Handle::new();
    spawn_tls_server(std_listener, tls, router, handle.clone());

    SmokeInstance {
        state,
        addr,
        handle,
    }
}

/// Spawn an `axum-server` TLS listener that serves `router` on
/// `std_listener` until `handle.graceful_shutdown(...)` is called.
/// Logs a warning if the server task exits early — that surfaces a
/// TLS init failure (wrong cert format, missing crypto provider)
/// rather than letting the test silently time-out on the first
/// outbound request.
fn spawn_tls_server(
    std_listener: TcpListener,
    tls: RustlsConfig,
    router: Router,
    handle: axum_server::Handle<SocketAddr>,
) {
    tokio::spawn(async move {
        let server = axum_server::from_tcp_rustls(std_listener, tls)
            .expect("axum-server from_tcp_rustls")
            .handle(handle);
        if let Err(e) = server
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await
        {
            tracing::warn!(error = %e, "smoke-test TLS server exited with error");
        }
    });
}

/// Generate a fresh self-signed cert valid for `127.0.0.1`. Lives for
/// the duration of the test only — no on-disk artifacts, no cert
/// rotation logic. `rcgen::generate_simple_self_signed` fills in a
/// sensible Subject Alternative Names list from the strings we pass
/// (the only thing reqwest cares about, since we also disable name
/// verification).
fn loopback_self_signed_cert() -> (Vec<u8>, Vec<u8>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["127.0.0.1".to_string(), "localhost".to_string()])
            .expect("generate self-signed cert");
    let cert_pem = cert.pem().into_bytes();
    let key_pem = signing_key.serialize_pem().into_bytes();
    (cert_pem, key_pem)
}

/// Build a `reqwest::Client` that trusts the smoke test's self-signed
/// cert. The production `ReqwestTransport::default_client()` would
/// reject it on cert-chain validation; we explicitly bypass that
/// check for loopback because the test is the only thing that's ever
/// going to talk to this listener.
fn smoke_test_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        // The two "danger" toggles together accept any self-signed
        // cert from any name — that's exactly what a loopback test
        // needs and what production must never do. The transport's
        // SSRF policy (`PRISMOIRE_FEDERATION_ALLOW_PRIVATE_TARGETS`)
        // is the second half of the "only loopback, only smoke test"
        // promise.
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .http2_prior_knowledge() // skip ALPN dance for loopback
        .user_agent("prismoire/federation-smoke")
        .build()
        .expect("smoke-test reqwest client")
}

// ---------------------------------------------------------------------------
// CBOR helpers (copied tersely from federation_phase5*.rs — these test
// crates can't share a private helper module without exposing it to
// every other test file).
// ---------------------------------------------------------------------------

fn encode_wire(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("p".into()), Value::Bytes(payload.to_vec())),
        (Value::Text("s".into()), Value::Bytes(signature.to_vec())),
    ]);
    let mut buf = Vec::with_capacity(payload.len() + signature.len() + 16);
    ciborium::ser::into_writer(&m, &mut buf).expect("ser");
    buf
}

fn encode_edges_body(wires: &[Vec<u8>]) -> Vec<u8> {
    let arr: Vec<Value> = wires.iter().map(|w| Value::Bytes(w.clone())).collect();
    let body = Value::Map(vec![(Value::Text("edges".into()), Value::Array(arr))]);
    let mut buf = Vec::with_capacity(64 + wires.iter().map(|w| w.len()).sum::<usize>());
    ciborium::ser::into_writer(&body, &mut buf).expect("ser");
    buf
}

async fn insert_user_with_pubkey(db: &SqlitePool, id: &str, display_name: &str, pubkey: &[u8; 32]) {
    let pubkey_slice: &[u8] = pubkey.as_slice();
    let skeleton = display_name.to_lowercase();
    sqlx::query!(
        "INSERT INTO users (id, display_name, signup_method, public_key, display_name_skeleton) \
         VALUES (?, ?, 'admin', ?, ?)",
        id,
        display_name,
        pubkey_slice,
        skeleton,
    )
    .execute(db)
    .await
    .expect("insert user");
}

// ---------------------------------------------------------------------------
// The smoke scenario
// ---------------------------------------------------------------------------

/// Two real Prismoire AppStates over loopback HTTPS run through the
/// full Phase-5 happy path:
///
/// 1. **Handshake.** A invokes `operator_initiate_peer_request`,
///    which signs and POSTs `/federation/v1/peer-request` to B via
///    real TLS. B's handler stores the request as `pending_inbound`,
///    returns `202`. The operator on B then calls
///    `operator_accept_peer_request`, which signs and POSTs
///    `/federation/v1/peer-response` back to A. Both ends are now
///    `active`.
/// 2. **Edge push.** A signs a trust-edge (alice → bob) and POSTs
///    `/federation/v1/edges` to B with the §6.5 envelope header. B
///    persists the canonical bytes to `signed_objects` and projects
///    into `trust_edges`. Verified by reading B's DB directly.
///
/// Step 2's assertion is the load-bearing part: the §6 envelope
/// header has to survive `reqwest`'s header serialisation, the body
/// has to survive HTTP/2 framing byte-for-byte, and the §6.5
/// signature has to verify against the bytes B reconstructs from the
/// inbound `Request<Bytes>`. Any drift between the in-process
/// transport (`tower::oneshot`) and the production transport
/// (`reqwest`) shows up here as a `401` from the envelope verifier
/// or a `400` from the per-edge state machine, not as a confusing
/// downstream failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handshake_and_edge_push_over_loopback_https() {
    install_crypto_provider();

    // One self-signed cert, one reqwest client, shared between both
    // instances. Reusing the client also exercises connection
    // pooling — every outbound request after the first reuses an
    // already-established TLS connection per origin.
    let (cert_pem, key_pem) = loopback_self_signed_cert();
    let tls = RustlsConfig::from_pem(cert_pem, key_pem)
        .await
        .expect("rustls config from self-signed PEM");
    let client = smoke_test_client();

    let a = spawn_smoke_instance(client.clone(), tls.clone()).await;
    let b = spawn_smoke_instance(client.clone(), tls.clone()).await;

    // The listeners spawn on `tokio::spawn`'d tasks; give them a
    // chance to reach the accept loop before the first dial.
    // axum-server's `serve()` future is hot — the listener is
    // accepting by the time the future is polled once — so a tiny
    // yield is enough. (We'd otherwise race a connect against an
    // accept loop that hasn't entered its first `.await` yet.)
    tokio::task::yield_now().await;

    // ----- Step 1: handshake A ↔ B ---------------------------------
    let a_transport: Arc<dyn FederationTransport> = a.state.federation_transport.clone();
    let request_id = operator_initiate_peer_request(
        &a.state.db,
        &a.state.instance_key,
        &a.state.instance_domain,
        &a_transport,
        *b.state.instance_key.public_bytes(),
        &b.state.instance_domain,
        vec!["edge-sync".into(), "content-sync".into()],
        None,
    )
    .await
    .expect("A → B /peer-request must succeed over loopback HTTPS");

    let b_transport: Arc<dyn FederationTransport> = b.state.federation_transport.clone();
    operator_accept_peer_request(
        &b.state.db,
        &b.state.instance_key,
        &b.state.instance_domain,
        &b_transport,
        request_id,
    )
    .await
    .expect("B → A /peer-response must succeed over loopback HTTPS");

    // Both `peers` tables now hold an `active` row for the other side.
    assert_active_peer(&a.state.db, b.state.instance_key.public_bytes()).await;
    assert_active_peer(&b.state.db, a.state.instance_key.public_bytes()).await;

    // ----- Step 2: A pushes a signed trust-edge to B ---------------
    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let bob_pub = bob_key.verifying_key().to_bytes();
    insert_user_with_pubkey(&b.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&b.state.db, "user-bob", "bob", &bob_pub).await;

    let signed = sign_trust_edge_with_key(
        &alice_key,
        &bob_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    );
    let wire = encode_wire(&signed.payload, &signed.signature);
    let body = encode_edges_body(&[wire]);

    // The push uses the same `operator_initiate_peer_request`-style
    // signed dispatch the forwarder uses in production: build a
    // signed envelope header against the path + body, hand the
    // assembled `http::Request<Bytes>` to the transport. Doing it
    // through helpers from `federation::envelope` instead of the
    // multi-instance harness's `send_envelope_signed` keeps the test
    // honest — we're explicitly NOT using `tower::oneshot` here.
    let path = "/federation/v1/edges";
    let header = prismoire_server::federation::envelope::sign_outbound(
        &a.state.instance_key,
        *b.state.instance_key.public_bytes(),
        &http::Method::POST,
        path,
        &body,
    );
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(path)
        .header(
            http::header::CONTENT_TYPE,
            prismoire_server::federation::identity::CBOR_CONTENT_TYPE,
        )
        .header(prismoire_server::federation::envelope::AUTH_HEADER, header)
        .body(axum::body::Bytes::from(body))
        .expect("build push request");
    let resp = a_transport
        .request(
            &prismoire_server::federation::transport::PeerId::from_bytes(
                *b.state.instance_key.public_bytes(),
            ),
            request,
        )
        .await
        .expect("/edges push over loopback HTTPS");
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "push must 200 (body: {:?})",
        resp.body(),
    );

    // B's tables now hold the signed object and the projected edge.
    // This is the load-bearing assertion: if any byte drifted across
    // the real-TLS round-trip, the envelope verify would have 401'd
    // (no signed_objects row written) or the per-edge `verify`
    // would have rejected (signed_objects row but no trust_edges
    // row).
    let hash_slice: &[u8] = signed.canonical_hash.as_slice();
    let stored = sqlx::query!(
        "SELECT inner_class, payload FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("signed_objects row on B");
    assert_eq!(stored.inner_class, "trust-edge");
    assert_eq!(
        stored.payload.as_deref(),
        Some(signed.payload.as_slice()),
        "payload bytes round-tripped verbatim through real HTTPS",
    );
    let projection = sqlx::query!(
        "SELECT trust_type FROM trust_edges \
         WHERE source_user = 'user-alice' AND target_user = 'user-bob'",
    )
    .fetch_one(&b.state.db)
    .await
    .expect("trust_edges projection on B");
    assert_eq!(projection.trust_type, "trust");

    // ----- Teardown -------------------------------------------------
    // Free the loopback ports promptly so a second smoke-test run in
    // the same process (cargo test reuses test binaries within a
    // single invocation) can rebind. The 100 ms drain budget is
    // overkill for an idle loopback listener — the listener has no
    // in-flight requests by the time we reach here — but it keeps
    // the shutdown sequence robust if a future test extension grows
    // a longer handshake.
    a.handle.graceful_shutdown(Some(Duration::from_millis(100)));
    b.handle.graceful_shutdown(Some(Duration::from_millis(100)));
}

/// Assert that the local `peers` table has an `active` row keyed by
/// `peer_pubkey`. Pulled into a helper so the two symmetric checks
/// after the handshake stay short.
async fn assert_active_peer(db: &SqlitePool, peer_pubkey: &[u8; 32]) {
    let pubkey_slice: &[u8] = peer_pubkey.as_slice();
    let row = sqlx::query!(
        "SELECT status FROM peers WHERE instance_pubkey = ?",
        pubkey_slice,
    )
    .fetch_one(db)
    .await
    .expect("peers row");
    assert_eq!(
        row.status, "active",
        "handshake must converge both sides to `active`",
    );
}
