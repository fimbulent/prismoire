<script lang="ts">
	import { slide } from 'svelte/transition';

	interface Props {
		saving?: boolean;
		error?: string | null;
		onsubmit: (body: string) => void;
		oncancel: () => void;
	}

	let { saving = false, error = null, onsubmit, oncancel }: Props = $props();

	let body = $state('');

	function handleSubmit() {
		const text = body;
		body = '';
		onsubmit(text);
	}
</script>

<div class="mt-3" transition:slide={{ duration: 150 }}>
	<textarea
		bind:value={body}
		class="w-full min-h-24 bg-bg border border-border rounded-md text-text-primary font-mono text-sm p-3 resize-y leading-relaxed focus:outline-none focus:border-accent-muted placeholder:text-text-muted"
		placeholder="Reply to comment..."
	></textarea>
	{#if error}
		<div class="text-danger text-sm mt-1">{error}</div>
	{/if}
	<div class="mt-2 flex justify-end gap-3 items-center">
		<span class="text-xs text-text-muted mr-auto">Markdown supported</span>
		<button
			onclick={oncancel}
			disabled={saving}
			class="font-sans text-sm px-4 py-2 rounded-md cursor-pointer border border-border bg-transparent text-text-secondary font-medium hover:bg-bg-hover hover:text-text-primary disabled:opacity-50"
		>Cancel</button>
		<button
			onclick={handleSubmit}
			disabled={saving || body.trim() === ''}
			class="font-sans text-sm px-4 py-2 rounded-md cursor-pointer border border-accent bg-accent text-bg font-medium hover:opacity-90 disabled:opacity-50 transition-opacity duration-150"
		>{saving ? 'Posting…' : 'Post reply'}</button>
	</div>
</div>
