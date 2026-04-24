<script lang="ts">
	import { deleteRoom, deleteUser } from '$lib/api/admin';
	import { searchRooms, type RoomChip } from '$lib/api/rooms';
	import { searchUsers, type UserChip } from '$lib/api/users';
	import Autocomplete from '$lib/components/ui/Autocomplete.svelte';
	import { errorMessage } from '$lib/i18n/errors';
	import { invalidateAll } from '$app/navigation';

	// --- Delete Room state --------------------------------------------------
	// `roomQuery` is the bindable text in the autocomplete input.
	// `selectedRoom` is the row the user actually picked — we keep it
	// separate because the slug in the input might drift away from the
	// selection as the user types, and the delete confirmation must
	// always target a specific room id.
	let roomQuery = $state('');
	let selectedRoom = $state<RoomChip | null>(null);
	let roomReason = $state('');
	let roomConfirm = $state('');
	let roomError = $state<string | null>(null);
	let roomSuccess = $state<string | null>(null);
	let roomSaving = $state(false);

	const roomConfirmOk = $derived(
		selectedRoom !== null && roomConfirm === selectedRoom.slug
	);
	const roomReady = $derived(
		selectedRoom !== null && roomConfirmOk && roomReason.trim().length > 0 && !roomSaving
	);

	async function confirmDeleteRoom() {
		if (!selectedRoom) return;
		roomError = null;
		roomSuccess = null;
		roomSaving = true;
		try {
			await deleteRoom(selectedRoom.id, roomReason.trim(), roomConfirm);
			roomSuccess = `Deleted room ${selectedRoom.slug}.`;
			roomQuery = '';
			selectedRoom = null;
			roomReason = '';
			roomConfirm = '';
			await invalidateAll();
		} catch (e) {
			roomError = errorMessage(e, 'Failed to delete room');
		} finally {
			roomSaving = false;
		}
	}

	// --- Delete User state --------------------------------------------------
	let userQuery = $state('');
	let selectedUser = $state<UserChip | null>(null);
	let userReason = $state('');
	let userConfirm = $state('');
	let userError = $state<string | null>(null);
	let userSuccess = $state<string | null>(null);
	let userSaving = $state(false);

	const userConfirmOk = $derived(
		selectedUser !== null && userConfirm === selectedUser.display_name
	);
	const userReady = $derived(
		selectedUser !== null && userConfirmOk && userReason.trim().length > 0 && !userSaving
	);

	async function confirmDeleteUser() {
		if (!selectedUser) return;
		userError = null;
		userSuccess = null;
		userSaving = true;
		try {
			await deleteUser(selectedUser.id, userReason.trim(), userConfirm);
			userSuccess = `Deleted user ${selectedUser.display_name}.`;
			userQuery = '';
			selectedUser = null;
			userReason = '';
			userConfirm = '';
		} catch (e) {
			userError = errorMessage(e, 'Failed to delete user');
		} finally {
			userSaving = false;
		}
	}
</script>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-16">
	<div class="mt-2 mb-3 text-xs font-semibold uppercase tracking-wider text-danger">
		Danger Zone
	</div>

	<!-- Delete Room -->
	<div class="border border-danger/30 bg-danger/5 rounded-md p-5 mb-4">
		<div class="text-sm font-semibold text-text-primary mb-1">
			Delete Room &amp; All Threads
		</div>
		<div class="text-xs text-text-muted mb-3">
			Permanently deletes a room, all threads within it, and all posts in
			those threads. This action is irreversible and will be logged.
		</div>
		<div class="flex gap-3 items-end flex-wrap">
			<div class="flex-1 min-w-60">
				<label for="delete-room-query" class="text-xs text-text-muted block mb-1">
					Room to delete
				</label>
				<Autocomplete
					id="delete-room-query"
					bind:value={roomQuery}
					fetcher={(q) => searchRooms(q)}
					formatLabel={(r: RoomChip) => r.slug}
					itemKey={(r: RoomChip) => r.id}
					onSelect={(r) => {
						selectedRoom = r;
						roomConfirm = '';
					}}
					onClear={() => {
						selectedRoom = null;
					}}
					placeholder="Start typing a room slug..."
				>
					{#snippet renderItem(r: RoomChip)}
						<div class="flex items-baseline justify-between gap-3">
							<span class="text-text-primary font-medium">{r.slug}</span>
							<span class="text-xs text-text-muted">
								{r.recent_thread_count}
								{r.recent_thread_count === 1 ? 'thread' : 'threads'}
								{r.activity_window_days >= 7 ? 'this week' : `last ${r.activity_window_days}d`}
							</span>
						</div>
					{/snippet}
				</Autocomplete>
			</div>
			<div class="flex-1 min-w-40">
				<label for="delete-room-reason" class="text-xs text-text-muted block mb-1">
					Reason (required)
				</label>
				<input
					id="delete-room-reason"
					type="text"
					bind:value={roomReason}
					placeholder="Why is this room being deleted?"
					class="w-full bg-bg border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted font-sans"
				/>
			</div>
			<div class="flex-1 min-w-40">
				<label for="delete-room-confirm" class="text-xs text-text-muted block mb-1">
					Type room slug to confirm
				</label>
				<input
					id="delete-room-confirm"
					type="text"
					bind:value={roomConfirm}
					placeholder={selectedRoom ? selectedRoom.slug : 'e.g. spam_room'}
					disabled={!selectedRoom}
					class="w-full bg-bg border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted font-sans disabled:opacity-50 disabled:cursor-not-allowed"
				/>
			</div>
			<button
				type="button"
				onclick={confirmDeleteRoom}
				disabled={!roomReady}
				class="font-sans text-sm px-4 py-2 rounded-md cursor-pointer border border-danger bg-danger/15 text-danger font-medium hover:bg-danger/25 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
			>
				{roomSaving ? 'Deleting…' : 'Delete Room'}
			</button>
		</div>
		{#if selectedRoom}
			<div class="mt-3 p-3 bg-bg rounded-md border border-border-subtle text-xs text-text-muted">
				Selected:
				<span class="text-text-primary font-semibold">{selectedRoom.slug}</span>
				— {selectedRoom.recent_thread_count}
				{selectedRoom.recent_thread_count === 1 ? 'thread' : 'threads'}
				{selectedRoom.activity_window_days >= 7
					? 'this week'
					: `last ${selectedRoom.activity_window_days}d`}
			</div>
		{/if}
		{#if roomError}
			<div class="text-danger text-xs mt-3">{roomError}</div>
		{/if}
		{#if roomSuccess}
			<div class="text-success text-xs mt-3">{roomSuccess}</div>
		{/if}
	</div>

	<!-- Delete User -->
	<div class="border border-danger/30 bg-danger/5 rounded-md p-5 mb-4">
		<div class="text-sm font-semibold text-text-primary mb-1">
			Delete User &amp; All Posts
		</div>
		<div class="text-xs text-text-muted mb-3">
			Permanently deletes a user account, retracts all their posts, and
			removes all their trust and distrust edges. This action is irreversible
			and will be logged.
		</div>
		<div class="flex gap-3 items-end flex-wrap">
			<div class="flex-1 min-w-60">
				<label for="delete-user-query" class="text-xs text-text-muted block mb-1">
					User
				</label>
				<Autocomplete
					id="delete-user-query"
					bind:value={userQuery}
					fetcher={(q) => searchUsers(q)}
					formatLabel={(u: UserChip) => u.display_name}
					itemKey={(u: UserChip) => u.id}
					onSelect={(u) => {
						selectedUser = u;
						userConfirm = '';
					}}
					onClear={() => {
						selectedUser = null;
					}}
					openOnFocus={false}
					placeholder="Start typing a display name..."
				>
					{#snippet renderItem(u: UserChip)}
						<div class="flex items-baseline justify-between gap-3">
							<span class="text-text-primary font-medium">{u.display_name}</span>
							<span class="flex items-center gap-1 text-xs">
								{#if u.role === 'admin'}
									<span class="text-accent font-semibold uppercase">admin</span>
								{/if}
								{#if u.status !== 'active'}
									<span class="text-danger font-semibold uppercase">{u.status}</span>
								{/if}
							</span>
						</div>
					{/snippet}
				</Autocomplete>
			</div>
			<div class="flex-1 min-w-40">
				<label for="delete-user-reason" class="text-xs text-text-muted block mb-1">
					Reason (required)
				</label>
				<input
					id="delete-user-reason"
					type="text"
					bind:value={userReason}
					placeholder="Why is this user being deleted?"
					class="w-full bg-bg border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted font-sans"
				/>
			</div>
			<div class="flex-1 min-w-40">
				<label for="delete-user-confirm" class="text-xs text-text-muted block mb-1">
					Type display name to confirm
				</label>
				<input
					id="delete-user-confirm"
					type="text"
					bind:value={userConfirm}
					placeholder={selectedUser ? selectedUser.display_name : 'e.g. siltrunner'}
					disabled={!selectedUser}
					class="w-full bg-bg border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted font-sans disabled:opacity-50 disabled:cursor-not-allowed"
				/>
			</div>
			<button
				type="button"
				onclick={confirmDeleteUser}
				disabled={!userReady}
				class="font-sans text-sm px-4 py-2 rounded-md cursor-pointer border border-danger bg-danger/15 text-danger font-medium hover:bg-danger/25 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
			>
				{userSaving ? 'Deleting…' : 'Delete User'}
			</button>
		</div>

		{#if selectedUser}
			<div class="mt-3 p-3 bg-bg rounded-md border border-border-subtle flex items-center gap-3">
				<div
					class="w-8 h-8 rounded-full bg-bg-surface-raised border border-border flex items-center justify-center text-sm font-bold text-accent uppercase"
				>
					{selectedUser.display_name.slice(0, 1)}
				</div>
				<div class="flex-1">
					<div class="text-sm font-semibold text-text-primary">
						{selectedUser.display_name}
					</div>
					<div class="text-xs text-text-muted">
						{selectedUser.role === 'admin' ? 'Admin · ' : ''}Status: {selectedUser.status}
					</div>
				</div>
			</div>
		{/if}

		{#if userError}
			<div class="text-danger text-xs mt-3">{userError}</div>
		{/if}
		{#if userSuccess}
			<div class="text-success text-xs mt-3">{userSuccess}</div>
		{/if}
	</div>
</div>
