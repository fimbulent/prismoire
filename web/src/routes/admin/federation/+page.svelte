<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import {
		acceptPeer,
		defederatePeer,
		initiatePeer,
		previewPeer,
		type PeerPreview,
		type PeerStatus,
		type PeerView
	} from '$lib/api/federation';
	import KeyBadge from '$lib/components/pubkey/KeyBadge.svelte';
	import { relativeTime } from '$lib/format';
	import { keyLabel } from '$lib/pubkey/keyLabel';
	import { toast } from '$lib/components/ui/toast.svelte';
	import { errorMessage } from '$lib/i18n/errors';

	let { data } = $props();

	// --- Stage 1/2 federate flow --------------------------------------
	let domainInput = $state('');
	let previewing = $state(false);
	let preview = $state<PeerPreview | null>(null);
	// Capabilities the operator wants to propose. Seeded from the remote's
	// advertised set when a preview lands; the server intersects this with
	// our own advertised set at handshake time.
	let proposedCaps = $state<Set<string>>(new Set());
	let introduction = $state('');
	let federating = $state(false);

	// --- Per-peer action state ----------------------------------------
	let busyPubkey = $state<string | null>(null);
	// Pubkey awaiting an explicit defederate confirmation (active peers
	// only — those trigger a wire DELETE the peer can't be un-told).
	let confirmPubkey = $state<string | null>(null);
	// Pubkeys whose detail panel is expanded. The short glyph+name label is
	// recognition-only (~37 bits, grindable); details like the full fingerprint
	// and agreed capabilities live behind the expander, collapsed by default.
	// pending_inbound rows are forced open (see isExpanded) so the fingerprint
	// is verifiable before the operator accepts.
	let expandedRows = $state<Set<string>>(new Set());

	function toggleRow(pubkey: string) {
		const next = new Set(expandedRows);
		if (next.has(pubkey)) next.delete(pubkey);
		else next.add(pubkey);
		expandedRows = next;
	}

	const isExpanded = (peer: PeerView) =>
		peer.status === 'pending_inbound' || expandedRows.has(peer.pubkey_hex);

	/// Group a hex pubkey into space-separated 4-char chunks so an
	/// operator can read a fingerprint aloud / compare it by eye.
	function fingerprint(hex: string): string {
		return (hex.match(/.{1,4}/g) ?? []).join(' ');
	}

	function statusLabel(s: PeerStatus): string {
		switch (s) {
			case 'active':
				return 'Active';
			case 'pending_outbound':
				return 'Request sent';
			case 'pending_inbound':
				return 'Awaiting your accept';
			case 'rejected':
				return 'Rejected';
			case 'terminated':
				return 'Terminated';
			default:
				return s;
		}
	}

	function statusClass(s: PeerStatus): string {
		switch (s) {
			case 'active':
				return 'bg-success/15 text-success';
			case 'pending_inbound':
				return 'bg-accent/15 text-accent';
			case 'pending_outbound':
				return 'bg-bg-surface text-text-secondary border border-border';
			default:
				return 'bg-danger/10 text-text-muted';
		}
	}

	async function handlePreview() {
		const domain = domainInput.trim();
		if (domain === '') return;
		previewing = true;
		preview = null;
		try {
			const result = await previewPeer(domain);
			preview = result;
			proposedCaps = new Set(result.capabilities);
		} catch (e) {
			toast.error(errorMessage(e, 'Could not look up that instance'));
		} finally {
			previewing = false;
		}
	}

	function toggleCap(cap: string) {
		const next = new Set(proposedCaps);
		if (next.has(cap)) next.delete(cap);
		else next.add(cap);
		proposedCaps = next;
	}

	function resetFederateForm() {
		domainInput = '';
		preview = null;
		proposedCaps = new Set();
		introduction = '';
	}

	const canFederate = $derived(
		preview !== null && !preview.is_self && preview.existing_status === null
	);

	async function handleFederate() {
		if (preview === null || !canFederate) return;
		federating = true;
		try {
			await initiatePeer({
				domain: preview.domain,
				pubkey_hex: preview.pubkey_hex,
				capabilities: [...proposedCaps],
				introduction: introduction.trim() === '' ? null : introduction.trim()
			});
			toast.success(`Federation request sent to ${preview.domain}.`);
			resetFederateForm();
			await invalidateAll();
		} catch (e) {
			toast.error(errorMessage(e, 'Failed to send federation request'));
		} finally {
			federating = false;
		}
	}

	async function handleAccept(peer: PeerView) {
		busyPubkey = peer.pubkey_hex;
		try {
			await acceptPeer(peer.pubkey_hex);
			toast.success(`Now federated with ${peer.domain}.`);
			await invalidateAll();
		} catch (e) {
			toast.error(errorMessage(e, 'Failed to accept federation request'));
		} finally {
			busyPubkey = null;
		}
	}

	// Non-active rows (pending / rejected / terminated) have no live
	// relationship to tear down, so they drop straight to a local
	// removal without the confirmation step.
	async function handleRemove(peer: PeerView) {
		busyPubkey = peer.pubkey_hex;
		try {
			const { action } = await defederatePeer(peer.pubkey_hex);
			toast.success(action === 'terminated' ? `Defederated from ${peer.domain}.` : 'Removed.');
			confirmPubkey = null;
			await invalidateAll();
		} catch (e) {
			toast.error(errorMessage(e, 'Failed to remove peer'));
		} finally {
			busyPubkey = null;
		}
	}
</script>

<svelte:head>
	<title>Admin Federation — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-16">
	<!-- This-instance identity ------------------------------------------ -->
	<section class="bg-bg-surface border border-border rounded-md p-5 mb-4">
		<div class="text-sm font-semibold text-text-primary mb-1">This Instance</div>
		<div class="text-xs text-text-muted mb-3">
			Share this domain and fingerprint with another instance's operator so they can confirm
			they're federating with you (and not an impostor).
		</div>
		<div class="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm items-center">
			<span class="text-text-muted">Domain</span>
			<span class="text-text-primary font-medium">{data.instance.domain}</span>
			<span class="text-text-muted">Identity</span>
			<KeyBadge pubkeyHex={data.instance.pubkey_hex} />
			<span class="text-text-muted">Fingerprint</span>
			<span class="text-text-secondary font-mono text-xs break-all"
				>{fingerprint(data.instance.pubkey_hex)}</span
			>
		</div>
	</section>

	<!-- Federate with a new instance ------------------------------------ -->
	<section class="bg-bg-surface border border-border rounded-md p-5 mb-4">
		<div class="text-sm font-semibold text-text-primary mb-1">Federate with an Instance</div>
		<div class="text-xs text-text-muted mb-3">
			Enter another instance's domain to look up its identity, then review and send a federation
			request.
		</div>

		<div class="flex flex-wrap items-end gap-3">
			<div class="flex-1 min-w-60">
				<label for="federate-domain" class="text-xs text-text-muted block mb-1">
					Instance domain
				</label>
				<input
					id="federate-domain"
					type="text"
					bind:value={domainInput}
					onkeydown={(e) => {
						if (e.key === 'Enter') handlePreview();
					}}
					placeholder="e.g. example.org"
					disabled={previewing}
					class="w-full bg-bg border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted font-sans"
				/>
			</div>
			<button
				type="button"
				onclick={handlePreview}
				disabled={previewing || domainInput.trim() === ''}
				class="font-sans text-sm px-4 py-2 rounded-md cursor-pointer border border-border bg-bg text-text-primary font-medium hover:border-accent-muted disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
			>
				{previewing ? 'Looking up…' : 'Look up'}
			</button>
		</div>

		{#if preview}
			<div class="mt-4 p-4 bg-bg rounded-md border border-border-subtle">
				<div class="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm mb-3 items-center">
					<span class="text-text-muted">Domain</span>
					<span class="text-text-primary font-medium">{preview.domain}</span>
					<span class="text-text-muted">Identity</span>
					<KeyBadge pubkeyHex={preview.pubkey_hex} />
					<span class="text-text-muted">Fingerprint</span>
					<span class="text-text-secondary font-mono text-xs break-all"
						>{fingerprint(preview.pubkey_hex)}</span
					>
					<span class="text-text-muted">Protocol</span>
					<span class="text-text-secondary"
						>{preview.protocol_versions.join(', ') || '—'}</span
					>
					{#if preview.instance_age_days !== null}
						<span class="text-text-muted">Age</span>
						<span class="text-text-secondary">{preview.instance_age_days} days</span>
					{/if}
					{#if preview.user_count_bucket}
						<span class="text-text-muted">Users</span>
						<span class="text-text-secondary">{preview.user_count_bucket}</span>
					{/if}
					{#if preview.announce}
						<span class="text-text-muted">Announce</span>
						<span class="text-text-secondary">{preview.announce}</span>
					{/if}
				</div>

				{#if preview.is_self}
					<div class="text-danger text-xs mb-2">
						This is your own instance — you can't federate with yourself.
					</div>
				{:else if preview.existing_status !== null}
					<div class="text-text-muted text-xs mb-2">
						You already have a relationship with this instance ({statusLabel(
							preview.existing_status
						)}). Manage it in the table below.
					</div>
				{:else}
					<div class="mb-3">
						<div class="text-xs text-text-muted mb-1">Capabilities to propose</div>
						{#if preview.capabilities.length === 0}
							<div class="text-xs text-text-muted">This instance advertises no capabilities.</div>
						{:else}
							<div class="flex flex-wrap gap-2">
								{#each preview.capabilities as cap (cap)}
									<label
										class="inline-flex items-center gap-1.5 text-xs text-text-secondary cursor-pointer select-none border border-border rounded-md px-2 py-1"
									>
										<input
											type="checkbox"
											checked={proposedCaps.has(cap)}
											onchange={() => toggleCap(cap)}
											class="accent-accent"
										/>
										{cap}
									</label>
								{/each}
							</div>
						{/if}
					</div>

					<div class="mb-3">
						<label for="federate-intro" class="text-xs text-text-muted block mb-1">
							Introduction (optional)
						</label>
						<textarea
							id="federate-intro"
							bind:value={introduction}
							rows="2"
							placeholder="A short note for the other operator."
							class="w-full bg-bg-surface border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted font-sans resize-y"
						></textarea>
					</div>

					<button
						type="button"
						onclick={handleFederate}
						disabled={federating}
						class="font-sans text-sm px-4 py-2 rounded-md cursor-pointer border border-accent bg-accent/15 text-accent font-medium hover:bg-accent/25 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
					>
						{federating ? 'Sending…' : `Federate with ${preview.domain}`}
					</button>
				{/if}
			</div>
		{/if}
	</section>

	<!-- Peer table ------------------------------------------------------- -->
	<section class="bg-bg-surface border border-border rounded-md p-5">
		<div class="text-sm font-semibold text-text-primary mb-3">Federated Instances</div>

		{#if data.peers.length === 0}
			<div class="text-xs text-text-muted">
				No peers yet. Use the form above to federate with an instance.
			</div>
		{:else}
			<div class="overflow-x-auto">
				<table class="w-full text-sm border-collapse">
					<thead>
						<tr class="text-left text-xs text-text-muted border-b border-border">
							<th class="font-medium pb-2 pr-2 w-6"><span class="sr-only">Expand</span></th>
							<th class="font-medium pb-2 pr-3">Instance</th>
							<th class="font-medium pb-2 pr-3">Status</th>
							<th class="font-medium pb-2 pr-3">Last handshake</th>
							<th class="font-medium pb-2 text-right">Actions</th>
						</tr>
					</thead>
					<tbody>
						{#each data.peers as peer (peer.pubkey_hex)}
							{@const caps =
								peer.status === 'active' ? peer.agreed_capabilities : peer.capabilities}
							{@const expanded = isExpanded(peer)}
							<tr class="align-top">
								<td class="py-3 pr-2">
									{#if peer.status === 'pending_inbound'}
										<!-- Forced open for verification; no toggle, just an
										open-state indicator. -->
										<span class="text-text-muted text-xs select-none" aria-hidden="true">▾</span>
									{:else}
										<button
											type="button"
											onclick={() => toggleRow(peer.pubkey_hex)}
											aria-expanded={expanded}
											aria-label="Toggle details for {peer.domain}"
											class="text-text-muted hover:text-text-secondary cursor-pointer transition-colors p-1 -m-1"
										>
											<span
												class="inline-block text-xs transition-transform {expanded
													? 'rotate-90'
													: ''}"
												aria-hidden="true">▸</span
											>
										</button>
									{/if}
								</td>
								<td class="py-3 pr-3">
									<div class="flex items-center gap-2">
										<KeyBadge pubkeyHex={peer.pubkey_hex} size={28} showName={false} />
										<div>
											<div class="text-text-primary font-medium">{peer.domain}</div>
											<div class="text-text-muted text-xs">{keyLabel(peer.pubkey_hex).name}</div>
										</div>
									</div>
								</td>
								<td class="py-3 pr-3">
									<span
										class="inline-block text-xs rounded-full px-2 py-0.5 whitespace-nowrap {statusClass(
											peer.status
										)}"
									>
										{statusLabel(peer.status)}
									</span>
									{#if peer.termination_reason}
										<div class="text-text-muted text-[0.65rem] mt-1">
											{peer.termination_reason}
										</div>
									{/if}
								</td>
								<td class="py-3 pr-3 text-text-muted text-xs whitespace-nowrap">
									{#if peer.last_handshake}
										<span title={peer.last_handshake}>{relativeTime(peer.last_handshake)}</span>
									{:else}
										—
									{/if}
								</td>
								<td class="py-3 text-right">
									{#if confirmPubkey === peer.pubkey_hex}
										<div class="text-xs text-danger mb-1">
											Defederate? This notifies {peer.domain} and stops all content exchange.
										</div>
										<div class="flex justify-end gap-2">
											<button
												type="button"
												onclick={() => handleRemove(peer)}
												disabled={busyPubkey === peer.pubkey_hex}
												class="font-sans text-xs px-3 py-1.5 rounded-md cursor-pointer border border-danger bg-danger/15 text-danger font-medium hover:bg-danger/25 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
											>
												{busyPubkey === peer.pubkey_hex ? 'Working…' : 'Confirm'}
											</button>
											<button
												type="button"
												onclick={() => (confirmPubkey = null)}
												disabled={busyPubkey === peer.pubkey_hex}
												class="font-sans text-xs px-3 py-1.5 rounded-md cursor-pointer border border-border bg-bg text-text-secondary hover:border-accent-muted disabled:opacity-50 transition-colors"
											>
												Cancel
											</button>
										</div>
									{:else}
										<div class="flex justify-end gap-2">
											{#if peer.status === 'pending_inbound'}
												<button
													type="button"
													onclick={() => handleAccept(peer)}
													disabled={busyPubkey === peer.pubkey_hex}
													class="font-sans text-xs px-3 py-1.5 rounded-md cursor-pointer border border-accent bg-accent/15 text-accent font-medium hover:bg-accent/25 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
												>
													{busyPubkey === peer.pubkey_hex ? 'Working…' : 'Accept'}
												</button>
												<button
													type="button"
													onclick={() => handleRemove(peer)}
													disabled={busyPubkey === peer.pubkey_hex}
													class="font-sans text-xs px-3 py-1.5 rounded-md cursor-pointer border border-border bg-bg text-text-secondary hover:border-accent-muted disabled:opacity-50 transition-colors"
												>
													Decline
												</button>
											{:else if peer.status === 'active'}
												<button
													type="button"
													onclick={() => (confirmPubkey = peer.pubkey_hex)}
													disabled={busyPubkey === peer.pubkey_hex}
													class="font-sans text-xs px-3 py-1.5 rounded-md cursor-pointer border border-danger bg-danger/15 text-danger font-medium hover:bg-danger/25 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
												>
													Defederate
												</button>
											{:else if peer.status === 'pending_outbound'}
												<button
													type="button"
													onclick={() => handleRemove(peer)}
													disabled={busyPubkey === peer.pubkey_hex}
													class="font-sans text-xs px-3 py-1.5 rounded-md cursor-pointer border border-border bg-bg text-text-secondary hover:border-accent-muted disabled:opacity-50 transition-colors"
												>
													Cancel request
												</button>
											{:else}
												<button
													type="button"
													onclick={() => handleRemove(peer)}
													disabled={busyPubkey === peer.pubkey_hex}
													class="font-sans text-xs px-3 py-1.5 rounded-md cursor-pointer border border-border bg-bg text-text-muted hover:border-accent-muted disabled:opacity-50 transition-colors"
												>
													Remove
												</button>
											{/if}
										</div>
									{/if}
								</td>
							</tr>
							<!-- Always mounted so CSS can animate open/close; Svelte's
							transition directives are unusable here (they write inline
							`style`, which the CSP blocks). The grid 0fr↔1fr trick
							animates intrinsic height with no fixed max. -->
							<tr>
								<td colspan="5" class="p-0 border-b border-border-subtle">
									<div
										class="grid transition-[grid-template-rows] duration-200 ease-out {expanded
											? 'grid-rows-[1fr]'
											: 'grid-rows-[0fr]'}"
									>
										<div class="overflow-hidden" aria-hidden={!expanded}>
											<div
												class="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm pl-8 pr-3 pb-3"
											>
												<span class="text-text-muted text-xs">
													{peer.status === 'pending_inbound' ? 'Verify fingerprint' : 'Fingerprint'}
												</span>
												<span class="text-text-secondary font-mono text-xs break-all">
													{fingerprint(peer.pubkey_hex)}
												</span>
												<span class="text-text-muted text-xs">Capabilities</span>
												<span class="text-text-secondary text-xs">
													{caps.length > 0 ? caps.join(', ') : '—'}
												</span>
											</div>
										</div>
									</div>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</section>
</div>
