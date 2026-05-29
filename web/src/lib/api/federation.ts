import { throwApiError, type FetchFn } from './auth';

interface FetchOpts {
	fetch?: FetchFn;
}

/** This-instance identity, surfaced so the operator can share their own
 * domain + fingerprint out-of-band with a peer admin. */
export interface InstanceIdentity {
	domain: string;
	/** Lowercase-hex Ed25519 instance signing pubkey (64 chars). */
	pubkey_hex: string;
}

/** Lifecycle status of a `peers` row, mirroring the Rust enum. */
export type PeerStatus =
	| 'pending_outbound'
	| 'pending_inbound'
	| 'active'
	| 'rejected'
	| 'terminated'
	| string;

export interface PeerView {
	pubkey_hex: string;
	domain: string;
	status: PeerStatus;
	direction: 'outbound' | 'inbound' | string;
	capabilities: string[];
	agreed_capabilities: string[];
	decision_message: string | null;
	termination_reason: string | null;
	first_seen: string;
	last_handshake: string | null;
}

export interface PeersListResponse {
	instance: InstanceIdentity;
	peers: PeerView[];
}

/** Remote instance's self-reported identity card, plus two
 * locally-computed hints the UI needs before offering "federate". */
export interface PeerPreview {
	domain: string;
	pubkey_hex: string;
	protocol_versions: number[];
	capabilities: string[];
	announce: string | null;
	instance_age_days: number | null;
	user_count_bucket: string | null;
	/** True when the probed instance is this instance. */
	is_self: boolean;
	/** Status of an existing peer row for this pubkey, if any. */
	existing_status: PeerStatus | null;
}

export interface InitiateResponse {
	/** Lowercase-hex 16-byte handshake correlation id. */
	request_id: string;
}

export interface DefederateResponse {
	/** `'terminated'` when a wire DELETE went out, `'removed'` for a
	 * local-only row cleanup. */
	action: 'terminated' | 'removed';
}

export async function listPeers(opts: FetchOpts = {}): Promise<PeersListResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/admin/federation/peers');
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function previewPeer(domain: string, opts: FetchOpts = {}): Promise<PeerPreview> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/admin/federation/preview', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ domain })
	});
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function initiatePeer(
	args: {
		domain: string;
		pubkey_hex: string;
		capabilities: string[];
		introduction?: string | null;
	},
	opts: FetchOpts = {}
): Promise<InitiateResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/admin/federation/peers', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			domain: args.domain,
			pubkey_hex: args.pubkey_hex,
			capabilities: args.capabilities,
			introduction: args.introduction ?? null
		})
	});
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function acceptPeer(pubkeyHex: string, opts: FetchOpts = {}): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(
		`/api/admin/federation/peers/${encodeURIComponent(pubkeyHex)}/accept`,
		{ method: 'POST' }
	);
	if (!res.ok) await throwApiError(res);
}

export async function defederatePeer(
	pubkeyHex: string,
	opts: FetchOpts = {}
): Promise<DefederateResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/admin/federation/peers/${encodeURIComponent(pubkeyHex)}`, {
		method: 'DELETE'
	});
	if (!res.ok) await throwApiError(res);
	return res.json();
}
