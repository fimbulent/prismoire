<script lang="ts">
	import { goto, invalidateAll } from '$app/navigation';
	import { updateSettings } from '$lib/api/settings';
	import { exportMyData, deleteMyAccount } from '$lib/api/privacy';
	import { errorMessage } from '$lib/i18n/errors';
	import { toast } from '$lib/components/ui/toast.svelte';
	import { theme } from '$lib/stores/theme.svelte';
	import { themes, type ThemeId } from '$lib/themes';
	import { font } from '$lib/stores/font.svelte';
	import { fonts, type FontId } from '$lib/fonts';

	let exporting = $state(false);
	let exportError = $state<string | null>(null);

	let deleteArmed = $state(false);
	let deleteConfirmText = $state('');
	let deleting = $state(false);
	let deleteError = $state<string | null>(null);

	async function selectTheme(id: ThemeId) {
		theme.set(id);
		try {
			await updateSettings({ theme: id });
			toast.success('Theme saved.');
		} catch (e) {
			toast.error(errorMessage(e, 'Failed to save theme.'));
		}
	}

	async function selectFont(id: FontId) {
		font.set(id);
		try {
			await updateSettings({ font: id });
			toast.success('Font saved.');
		} catch (e) {
			toast.error(errorMessage(e, 'Failed to save font.'));
		}
	}

	async function handleExport() {
		exporting = true;
		exportError = null;
		try {
			await exportMyData();
		} catch (e) {
			exportError = errorMessage(e, 'Failed to export data');
		} finally {
			exporting = false;
		}
	}

	function armDelete() {
		deleteArmed = true;
		deleteConfirmText = '';
		deleteError = null;
	}

	function cancelDelete() {
		deleteArmed = false;
		deleteConfirmText = '';
		deleteError = null;
	}

	async function handleDelete() {
		if (deleteConfirmText !== 'delete my account') {
			deleteError = 'Type "delete my account" to confirm';
			return;
		}
		deleting = true;
		deleteError = null;
		try {
			await deleteMyAccount();
			// Session cookie is cleared by the DELETE response; re-run the
			// root layout load so `page.data.session` drops to null, then
			// send the user to /login.
			await invalidateAll();
			await goto('/login');
		} catch (e) {
			deleteError = errorMessage(e, 'Failed to delete account');
			deleting = false;
		}
	}
</script>

<svelte:head>
	<title>Settings — Prismoire</title>
</svelte:head>

<style>
	/* The font swatch in the picker uses `var(--font-prose)`, which is
	   set by the `[data-font="…"]` blocks in `app.css`. Putting
	   `data-font` on the swatch (rather than `<html>`) overrides
	   `--font-prose` for the swatch's subtree only, so each swatch
	   previews its own family without affecting the rest of the page. */
	.font-preview {
		font-family: var(--font-prose);
	}
</style>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-16">
	<h1 class="text-lg font-bold mb-6">Settings</h1>

	<section>
		<h2 class="text-sm font-semibold text-text-secondary mb-3">Theme</h2>
		<div class="grid grid-cols-2 lg:grid-cols-3 gap-3">
			{#each themes as t (t.id)}
				<button
					onclick={() => selectTheme(t.id)}
					class="relative rounded-lg border-2 p-3 text-left transition-colors cursor-pointer"
					class:border-accent={theme.current === t.id}
					class:border-border-subtle={theme.current !== t.id}
					class:hover:border-border={theme.current !== t.id}
				>
					<div data-theme={t.id} class="rounded-md overflow-hidden mb-2 border border-black/10 bg-[var(--bg)]">
						<div class="h-2 bg-[var(--bg-surface)]"></div>
						<div class="px-2 py-1.5 space-y-1">
							<div class="flex items-center gap-1.5">
								<div class="h-1.5 w-8 rounded-full bg-[var(--accent)]"></div>
								<div class="h-1.5 w-12 rounded-full bg-[var(--text-primary)]"></div>
							</div>
							<div class="h-1.5 w-16 rounded-full bg-[var(--text-secondary)]"></div>
							<div class="flex items-center gap-1">
								<div class="h-1.5 w-3 rounded-full bg-[var(--trust-direct)]"></div>
								<div class="h-1.5 w-3 rounded-full bg-[var(--trust-2hop)]"></div>
								<div class="h-1.5 w-3 rounded-full bg-[var(--trust-3hop)]"></div>
							</div>
						</div>
					</div>
					<div class="text-sm text-text-primary">
						{t.name}
					</div>
				</button>
			{/each}
		</div>
	</section>

	<section class="mt-10">
		<h2 class="text-sm font-semibold text-text-secondary mb-1">Prose font</h2>
		<p class="text-xs text-text-muted mb-3">
			Applies to post content only — interface elements keep the default UI font.
		</p>
		<div class="grid grid-cols-2 lg:grid-cols-3 gap-3">
			{#each fonts as f (f.id)}
				<button
					onclick={() => selectFont(f.id)}
					class="relative rounded-lg border-2 p-3 text-left transition-colors cursor-pointer"
					class:border-accent={font.current === f.id}
					class:border-border-subtle={font.current !== f.id}
					class:hover:border-border={font.current !== f.id}
				>
					<div data-font={f.id} class="font-preview text-text-primary">
						<div class="text-base">The quick brown fox</div>
						<div class="text-sm text-text-secondary italic">jumps over the lazy dog</div>
					</div>
					<div class="text-sm text-text-primary mt-2">
						{f.name}
						<span class="text-xs text-text-muted ml-1">{f.category === 'serif' ? 'Serif' : 'Sans'}</span>
					</div>
				</button>
			{/each}
		</div>
	</section>

	<section class="mt-10">
		<h2 class="text-sm font-semibold text-text-secondary mb-3">Your data</h2>
		<div class="bg-bg-surface border border-border rounded-md divide-y divide-border-subtle">
			<div class="p-4">
				<div class="flex flex-wrap items-start justify-between gap-3">
					<div>
						<div class="text-sm font-medium text-text-primary">Export my data</div>
						<div class="text-xs text-text-muted mt-0.5">
							Download a JSON file containing your profile, settings, signing
							keypair, credentials, outbound trust edges, and every thread,
							post, and report you authored.
						</div>
					</div>
					<button
						onclick={handleExport}
						disabled={exporting}
						class="text-xs px-3 py-1.5 rounded-md border border-border text-text-primary bg-bg-surface-raised hover:bg-bg-hover cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
					>
						{exporting ? 'Preparing…' : 'Export'}
					</button>
				</div>
				{#if exportError}
					<div class="text-xs text-danger mt-2">{exportError}</div>
				{/if}
			</div>

			<div class="p-4">
				<div class="flex flex-wrap items-start justify-between gap-3">
					<div>
						<div class="text-sm font-medium text-text-primary">Delete account</div>
						<div class="text-xs text-text-muted mt-0.5">
							Retracts all your posts, removes your passkeys, drops your
							sessions, and anonymises your profile. This cannot be undone.
						</div>
					</div>
					{#if !deleteArmed}
						<button
							onclick={armDelete}
							class="text-xs px-3 py-1.5 rounded-md border border-danger text-danger bg-danger/8 hover:bg-danger/15 cursor-pointer transition-colors"
						>
							Delete account…
						</button>
					{/if}
				</div>
				{#if deleteArmed}
					<div class="mt-3 border border-danger/40 bg-danger/5 rounded-md p-3">
						<div class="text-xs text-text-primary mb-2">
							Type <code class="px-1 rounded bg-bg-surface-raised">delete my account</code> to confirm.
						</div>
						<input
							type="text"
							bind:value={deleteConfirmText}
							disabled={deleting}
							autocomplete="off"
							class="w-full text-sm px-2 py-1 rounded border border-border bg-bg text-text-primary focus:outline-none focus:border-accent"
						/>
						{#if deleteError}
							<div class="text-xs text-danger mt-2">{deleteError}</div>
						{/if}
						<div class="flex gap-2 mt-3">
							<button
								onclick={handleDelete}
								disabled={deleting || deleteConfirmText !== 'delete my account'}
								class="text-xs px-3 py-1.5 rounded-md border border-danger text-danger bg-danger/15 hover:bg-danger/25 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
							>
								{deleting ? 'Deleting…' : 'Permanently delete'}
							</button>
							<button
								onclick={cancelDelete}
								disabled={deleting}
								class="text-xs px-3 py-1.5 rounded-md border border-border text-text-secondary hover:bg-bg-hover cursor-pointer disabled:opacity-50 transition-colors"
							>
								Cancel
							</button>
						</div>
					</div>
				{/if}
			</div>
		</div>
	</section>
</div>
