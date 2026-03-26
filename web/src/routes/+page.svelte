<script lang="ts">
	let healthStatus = $state<string | null>(null);
	let error = $state<string | null>(null);

	async function checkHealth() {
		try {
			const res = await fetch('/api/health');
			healthStatus = await res.text();
			error = null;
		} catch (e) {
			healthStatus = null;
			error = 'Could not reach API server';
		}
	}

	$effect(() => {
		checkHealth();
	});
</script>

<svelte:head>
	<title>Prismoire</title>
</svelte:head>

<div class="min-h-screen bg-bg flex items-center justify-center">
	<div class="bg-bg-surface border border-border rounded-md p-8 max-w-md w-full text-center">
		<h1 class="text-2xl font-bold text-accent mb-2 tracking-wide">Prismoire</h1>
		<p class="text-text-secondary text-sm mb-6">Trust-based community discussion</p>

		<div class="bg-bg-surface-raised border border-border-subtle rounded-md p-4">
			<p class="text-text-muted text-xs uppercase tracking-wider mb-2">API Status</p>
			{#if healthStatus}
				<span class="text-success font-mono font-semibold">{healthStatus}</span>
			{:else if error}
				<span class="text-danger font-mono text-sm">{error}</span>
			{:else}
				<span class="text-text-muted font-mono text-sm">checking...</span>
			{/if}
		</div>
	</div>
</div>
