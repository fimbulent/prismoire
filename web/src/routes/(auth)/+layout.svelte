<script lang="ts">
	let { children } = $props();
</script>

<div class="grid place-items-center p-4 min-h-[calc(100dvh-var(--nav-height))]">
	{@render children()}
</div>
