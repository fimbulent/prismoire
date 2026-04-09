import { applyTheme, DEFAULT_THEME, type ThemeId } from '$lib/themes';

let current = $state<ThemeId>(DEFAULT_THEME);

export const theme = {
	get current() {
		return current;
	},

	set(id: ThemeId) {
		current = id;
		applyTheme(id);
	},

	init(id: ThemeId) {
		current = id;
		applyTheme(id);
	}
};
