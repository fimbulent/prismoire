<script lang="ts">
	import { session } from '$lib/stores/session.svelte';
	import { goto } from '$app/navigation';

	$effect(() => {
		if (session.loading) return;
		if (session.isLoggedIn) {
			goto('/room/all', { replaceState: true });
		} else {
			goto('/public', { replaceState: true });
		}
	});
</script>
