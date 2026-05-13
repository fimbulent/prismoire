<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import { updateAdminConfig, type AdminConfigUpdate } from '$lib/api/admin';
	import { toast } from '$lib/components/ui/toast.svelte';
	import { errorMessage } from '$lib/i18n/errors';

	let { data } = $props();

	// The API stores rebuild-schedule values in milliseconds and the BFS
	// cache budget in bytes, but those raw units are awkward to type into
	// a form. The UI works in seconds and MiB and converts at the edges
	// (seeding from `data.config` and again when building the patch).
	const MS_PER_SEC = 1000;
	const BYTES_PER_MIB = 1024 * 1024;

	// Working copies of every editable field. They start as strings so
	// the `<input type="number">` round-trip works without coercing "" to 0.
	// Initialized empty here and re-seeded by the `$effect` below whenever
	// the server-side `data.config` changes (e.g. after `invalidateAll()`
	// following a successful save).
	let debounceSec = $state('');
	let minIntervalSec = $state('');
	let maxIntervalSec = $state('');
	let bfsCacheMiB = $state('');
	let sourceRepoUrl = $state('');

	$effect(() => {
		debounceSec = String(data.config.rebuild_debounce_ms / MS_PER_SEC);
		minIntervalSec = String(data.config.rebuild_min_interval_ms / MS_PER_SEC);
		maxIntervalSec = String(data.config.rebuild_max_interval_ms / MS_PER_SEC);
		bfsCacheMiB = String(data.config.rebuild_bfs_cache_bytes / BYTES_PER_MIB);
		sourceRepoUrl = data.config.source_repo_url ?? '';
	});

	let saving = $state(false);

	// Parse a numeric working-copy field back to its API-native unit.
	// Returns null for empty / whitespace-only / non-finite input so the
	// dirty check and save handler can both distinguish "user cleared the
	// field" from "user typed 0". Without this, `Number('') === 0` would
	// mark the form dirty and let Save submit 0, which the server then
	// rejects with a confusing range error.
	function parseScaled(raw: string, factor: number): number | null {
		const trimmed = raw.trim();
		if (trimmed === '') return null;
		const n = Number(trimmed);
		if (!Number.isFinite(n)) return null;
		return Math.round(n * factor);
	}

	const debounceMs = $derived(parseScaled(debounceSec, MS_PER_SEC));
	const minIntervalMs = $derived(parseScaled(minIntervalSec, MS_PER_SEC));
	const maxIntervalMs = $derived(parseScaled(maxIntervalSec, MS_PER_SEC));
	const bfsCacheBytes = $derived(parseScaled(bfsCacheMiB, BYTES_PER_MIB));

	// Any numeric field cleared or unparseable blocks save — there is no
	// sensible interpretation of "clear this knob" for these settings.
	const allNumericFieldsValid = $derived(
		debounceMs !== null &&
			minIntervalMs !== null &&
			maxIntervalMs !== null &&
			bfsCacheBytes !== null
	);

	// Derived view of "is this field still equal to what the server
	// last told us?" so the save button can disable itself when nothing
	// has changed, and so individual rows can show a "dirty" hint if we
	// add one later. A null (empty) numeric field still counts as dirty
	// so the user gets the visual cue that something needs attention,
	// but `allNumericFieldsValid` separately blocks the actual save.
	const dirty = $derived.by(() => {
		return (
			debounceMs !== data.config.rebuild_debounce_ms ||
			minIntervalMs !== data.config.rebuild_min_interval_ms ||
			maxIntervalMs !== data.config.rebuild_max_interval_ms ||
			bfsCacheBytes !== data.config.rebuild_bfs_cache_bytes ||
			sourceRepoUrl.trim() !== (data.config.source_repo_url ?? '')
		);
	});

	async function handleSave() {
		// Belt-and-braces: the Save button is disabled when any numeric
		// field is empty/unparseable, but guard here too so a stray
		// invocation can't slip past.
		if (!allNumericFieldsValid) return;

		const patch: AdminConfigUpdate = {};

		if (debounceMs !== null && debounceMs !== data.config.rebuild_debounce_ms) {
			patch.rebuild_debounce_ms = debounceMs;
		}
		if (minIntervalMs !== null && minIntervalMs !== data.config.rebuild_min_interval_ms) {
			patch.rebuild_min_interval_ms = minIntervalMs;
		}
		if (maxIntervalMs !== null && maxIntervalMs !== data.config.rebuild_max_interval_ms) {
			patch.rebuild_max_interval_ms = maxIntervalMs;
		}
		if (bfsCacheBytes !== null && bfsCacheBytes !== data.config.rebuild_bfs_cache_bytes) {
			patch.rebuild_bfs_cache_bytes = bfsCacheBytes;
		}
		const trimmedUrl = sourceRepoUrl.trim();
		if (trimmedUrl !== (data.config.source_repo_url ?? '')) {
			patch.source_repo_url = trimmedUrl;
		}

		if (Object.keys(patch).length === 0) return;

		saving = true;
		try {
			await updateAdminConfig(patch);
			toast.success('Config updated.');
			// Re-run the loader so the working copies re-seed from
			// the server's authoritative response.
			await invalidateAll();
		} catch (e) {
			toast.error(errorMessage(e, 'Failed to update config'));
		} finally {
			saving = false;
		}
	}

	function handleRevert() {
		debounceSec = String(data.config.rebuild_debounce_ms / MS_PER_SEC);
		minIntervalSec = String(data.config.rebuild_min_interval_ms / MS_PER_SEC);
		maxIntervalSec = String(data.config.rebuild_max_interval_ms / MS_PER_SEC);
		bfsCacheMiB = String(data.config.rebuild_bfs_cache_bytes / BYTES_PER_MIB);
		sourceRepoUrl = data.config.source_repo_url ?? '';
	}
</script>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-16">
	<section class="bg-bg-surface border border-border rounded-md p-5 mb-4">
		<div class="text-sm font-semibold text-text-primary mb-1">
			Trust Graph
		</div>
		<div class="text-xs text-text-muted mb-3">
			Settings that tune how the trust graph — which decides what each user can see — is
			recomputed and cached. The defaults are tuned for small instances; you generally don't
			need to change them unless your server is struggling or you have spare resources to
			dedicate.
		</div>

		<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
			<div>
				<label for="config-debounce-sec" class="text-xs text-text-muted block mb-1">
					Rebuild debounce (seconds)
				</label>
				<input
					id="config-debounce-sec"
					type="number"
					min="1"
					max="60"
					step="any"
					bind:value={debounceSec}
					disabled={saving}
					class="w-full bg-bg border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted font-sans"
				/>
				<div class="text-xs text-text-muted mt-1">
					How long to wait after a trust change before rebuilding the graph. Higher values
					improve performance by avoiding rebuilds when many trust changes happen close
					together; lower values make trust changes take effect more quickly. Raise this if
					your server is struggling with performance. If unsure, leave this at the default
					of 5 seconds.
				</div>
			</div>

			<div>
				<label for="config-min-interval-sec" class="text-xs text-text-muted block mb-1">
					Minimum rebuild interval (seconds)
				</label>
				<input
					id="config-min-interval-sec"
					type="number"
					min="1"
					max="3600"
					step="any"
					bind:value={minIntervalSec}
					disabled={saving}
					class="w-full bg-bg border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted font-sans"
				/>
				<div class="text-xs text-text-muted mt-1">
					The minimum time between consecutive graph rebuilds. Even if many trust changes
					arrive, the graph won't rebuild more often than this. Higher values reduce CPU
					load during busy periods at the cost of slightly staler trust results. If unsure,
					leave this at the default of 30 seconds.
				</div>
			</div>

			<div>
				<label for="config-max-interval-sec" class="text-xs text-text-muted block mb-1">
					Maximum rebuild interval (seconds)
				</label>
				<input
					id="config-max-interval-sec"
					type="number"
					min="1"
					max="3600"
					step="any"
					bind:value={maxIntervalSec}
					disabled={saving}
					class="w-full bg-bg border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted font-sans"
				/>
				<div class="text-xs text-text-muted mt-1">
					The longest the graph is allowed to go without rebuilding during sustained
					activity. Even under a steady stream of trust changes, the graph will be rebuilt
					at least this often so results don't get too stale. Lower values keep trust
					fresher at the cost of more frequent rebuilds. If unsure, leave this at the
					default of 300 seconds (5 minutes).
				</div>
			</div>

			<div>
				<label for="config-bfs-cache-mib" class="text-xs text-text-muted block mb-1">
					Trust graph cache budget (MiB)
				</label>
				<input
					id="config-bfs-cache-mib"
					type="number"
					min="1"
					max="4096"
					step="any"
					bind:value={bfsCacheMiB}
					disabled={saving}
					class="w-full bg-bg border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted font-sans"
				/>
				<div class="text-xs text-text-muted mt-1">
					Total memory budget for caching the trust graph. Improves site performance at the
					cost of increased memory usage. Practical suggestion: double this value if the
					cache is near its budget <em>and</em> the hit rate consistently falls below 60% —
					if the cache isn't full yet, raising the budget won't help. Current usage:
					<span class="text-text-secondary">
						{(data.overview.trust.bfs_cache_used_bytes / BYTES_PER_MIB).toFixed(1)} MiB
						of {(data.config.rebuild_bfs_cache_bytes / BYTES_PER_MIB).toFixed(0)} MiB
						({((data.overview.trust.bfs_cache_used_bytes / data.config.rebuild_bfs_cache_bytes) * 100).toFixed(1)}%)
					</span>, hit rate:
					<span class="text-text-secondary">
						{data.overview.trust.bfs_cache_hit_rate !== null
							? `${(data.overview.trust.bfs_cache_hit_rate * 100).toFixed(1)}%`
							: '—'}
					</span>.
				</div>
			</div>
		</div>
	</section>

	<section class="bg-bg-surface border border-border rounded-md p-5 mb-4">
		<div class="text-sm font-semibold text-text-primary mb-1">
			Source Code URL
		</div>
		<div class="text-xs text-text-muted mb-3">
			Public URL to this instance's source code. If you modified Prismoire, you <em>must</em> link to your
			modified source code here according to the terms of the
			<a class="text-link hover:text-link-hover" target="_blank" rel="nofollow ugc noopener noreferrer" href="https://www.gnu.org/licenses/agpl-3.0.en.html">AGPL license</a>.
			If you did not modify Prismoire's source code, link to Prismoire's
			<a class="text-link hover:text-link-hover" target="_blank" rel="nofollow ugc noopener noreferrer" href="https://codeberg.org/fimbulent/prismoire">public repository</a>.
			This link will appear in the site footer for all users.
		</div>

		<div>
			<label for="config-source-repo-url" class="text-xs text-text-muted block mb-1">
				URL
			</label>
			<input
				id="config-source-repo-url"
				type="url"
				bind:value={sourceRepoUrl}
				disabled={saving}
				placeholder="https://example.com/prismoire"
				class="w-full bg-bg border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted font-sans"
			/>
		</div>
	</section>

	<div class="flex justify-end gap-2">
		<button
			type="button"
			onclick={handleRevert}
			disabled={!dirty || saving}
			class="font-sans text-sm px-4 py-2 rounded-md cursor-pointer border border-border bg-bg text-text-secondary hover:bg-bg-hover hover:text-text-primary disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
		>
			Revert
		</button>
		<button
			type="button"
			onclick={handleSave}
			disabled={!dirty || !allNumericFieldsValid || saving}
			class="font-sans text-sm px-4 py-2 rounded-md cursor-pointer border border-accent bg-accent/15 text-accent font-medium hover:bg-accent/25 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
		>
			{saving ? 'Saving…' : 'Save changes'}
		</button>
	</div>
</div>

<style>
	/* Hide the spinner buttons on number inputs — the up/down arrows
	   add visual noise to a config page where users type exact values. */
	input[type='number']::-webkit-outer-spin-button,
	input[type='number']::-webkit-inner-spin-button {
		-webkit-appearance: none;
		margin: 0;
	}
	input[type='number'] {
		-moz-appearance: textfield;
		appearance: textfield;
	}
</style>
