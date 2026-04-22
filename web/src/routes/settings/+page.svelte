<script lang="ts">
	import { goto, invalidateAll } from '$app/navigation';
	import { updateSettings } from '$lib/api/settings';
	import { exportMyData, deleteMyAccount } from '$lib/api/privacy';
	import { errorMessage } from '$lib/i18n/errors';
	import { theme } from '$lib/stores/theme.svelte';
	import { themes, type ThemeId } from '$lib/themes';

	let savedId = $state<ThemeId | null>(null);

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
			savedId = id;
			setTimeout(() => {
				if (savedId === id) savedId = null;
			}, 1500);
		} catch {
			// Silently fail — the theme is already applied visually
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
	<title>Settings \u2014 Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-16">
	<h1 class="text-lg font-bold mb-6">Settings</h1>

	<section>
		<h2 class="text-sm font-semibold text-text-secondary mb-3">Theme</h2>
		<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
			{#each themes as t (t.id)}
				<button
					data-swatch={t.id}
					onclick={() => selectTheme(t.id)}
					class="relative rounded-lg border-2 p-3 text-left transition-colors cursor-pointer"
					class:border-accent={theme.current === t.id}
					class:border-border-subtle={theme.current !== t.id}
					class:hover:border-border={theme.current !== t.id}
				>
					<div class="rounded-md overflow-hidden mb-2 border border-black/10 bg-[var(--swatch-bg)]">
						<div class="h-2 bg-[var(--swatch-bg-surface)]"></div>
						<div class="px-2 py-1.5 space-y-1">
							<div class="flex items-center gap-1.5">
								<div class="h-1.5 w-8 rounded-full bg-[var(--swatch-accent)]"></div>
								<div class="h-1.5 w-12 rounded-full bg-[var(--swatch-text-primary)]"></div>
							</div>
							<div class="h-1.5 w-16 rounded-full bg-[var(--swatch-text-secondary)]"></div>
							<div class="flex items-center gap-1">
								<div class="h-1.5 w-3 rounded-full bg-[var(--swatch-trust-direct)]"></div>
								<div class="h-1.5 w-3 rounded-full bg-[var(--swatch-trust-2hop)]"></div>
								<div class="h-1.5 w-3 rounded-full bg-[var(--swatch-trust-3hop)]"></div>
							</div>
						</div>
					</div>
					<div class="text-sm text-text-primary">
						{t.name}
						{#if theme.current === t.id && savedId === t.id}
							<span class="text-xs text-success ml-1">Saved</span>
						{/if}
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
