<script lang="ts">
	import { session } from '$lib/stores/session.svelte';
	import { goto } from '$app/navigation';

	$effect(() => {
		if (session.loading) return;
		if (session.isLoggedIn) {
			goto('/area/all', { replaceState: true });
		} else {
			goto('/areas', { replaceState: true });
		}
	});
</script>
