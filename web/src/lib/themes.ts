export type ThemeId =
	| 'rose-pine'
	| 'nord'
	| 'everforest'
	| 'midnight-blue'
	| 'warm-ember'
	| 'stone'
	| 'moss'
	| 'coral'
	| 'blueprint';

export interface ThemeMeta {
	id: ThemeId;
	name: string;
	vars: Record<string, string>;
}

export const themes: ThemeMeta[] = [
	{
		id: 'rose-pine',
		name: 'Rosé Pine',
		vars: {
			'--bg': '#1a1a2e',
			'--bg-surface': '#22223a',
			'--bg-surface-dim': '#1e1e34',
			'--bg-surface-raised': '#2a2a44',
			'--bg-hover': '#32324e',
			'--text-primary': '#e0def4',
			'--text-secondary': '#908caa',
			'--text-muted': '#6e6a86',
			'--border': '#393552',
			'--border-subtle': '#2e2b45',
			'--accent': '#c4a7e7',
			'--accent-muted': '#8e7aab',
			'--trust-direct': '#9ccfd8',
			'--trust-2hop': '#f6c177',
			'--trust-3hop': '#ea9a97',
			'--trust-untrusted': '#6e6a86',
			'--link': '#c4a7e7',
			'--link-hover': '#e0def4',
			'--danger': '#eb6f92',
			'--success': '#9ccfd8'
		}
	},
	{
		id: 'nord',
		name: 'Nord',
		vars: {
			'--bg': '#2e3440',
			'--bg-surface': '#3b4252',
			'--bg-surface-dim': '#353c49',
			'--bg-surface-raised': '#434c5e',
			'--bg-hover': '#4c566a',
			'--text-primary': '#eceff4',
			'--text-secondary': '#d8dee9',
			'--text-muted': '#7b88a1',
			'--border': '#4c566a',
			'--border-subtle': '#434c5e',
			'--accent': '#88c0d0',
			'--accent-muted': '#5e81ac',
			'--trust-direct': '#a3be8c',
			'--trust-2hop': '#ebcb8b',
			'--trust-3hop': '#d08770',
			'--trust-untrusted': '#7b88a1',
			'--link': '#88c0d0',
			'--link-hover': '#8fbcbb',
			'--danger': '#bf616a',
			'--success': '#a3be8c'
		}
	},
	{
		id: 'everforest',
		name: 'Everforest',
		vars: {
			'--bg': '#272e33',
			'--bg-surface': '#2e383c',
			'--bg-surface-dim': '#2b3338',
			'--bg-surface-raised': '#374145',
			'--bg-hover': '#414b50',
			'--text-primary': '#d3c6aa',
			'--text-secondary': '#9da9a0',
			'--text-muted': '#7a8478',
			'--border': '#4f5b58',
			'--border-subtle': '#414b50',
			'--accent': '#a7c080',
			'--accent-muted': '#83c092',
			'--trust-direct': '#83c092',
			'--trust-2hop': '#dbbc7f',
			'--trust-3hop': '#e69875',
			'--trust-untrusted': '#7a8478',
			'--link': '#a7c080',
			'--link-hover': '#d3c6aa',
			'--danger': '#e67e80',
			'--success': '#83c092'
		}
	},
	{
		id: 'midnight-blue',
		name: 'Midnight Blue',
		vars: {
			'--bg': '#0b1222',
			'--bg-surface': '#111a2e',
			'--bg-surface-dim': '#0e1628',
			'--bg-surface-raised': '#182440',
			'--bg-hover': '#1e2d4a',
			'--text-primary': '#e2e8f0',
			'--text-secondary': '#94a3b8',
			'--text-muted': '#64748b',
			'--border': '#1e3a5f',
			'--border-subtle': '#162d4a',
			'--accent': '#38bdf8',
			'--accent-muted': '#0ea5e9',
			'--trust-direct': '#2dd4bf',
			'--trust-2hop': '#fbbf24',
			'--trust-3hop': '#f97316',
			'--trust-untrusted': '#64748b',
			'--link': '#38bdf8',
			'--link-hover': '#7dd3fc',
			'--danger': '#f43f5e',
			'--success': '#2dd4bf'
		}
	},
	{
		id: 'warm-ember',
		name: 'Warm Ember',
		vars: {
			'--bg': '#1c1917',
			'--bg-surface': '#272220',
			'--bg-surface-dim': '#221d1c',
			'--bg-surface-raised': '#332d2a',
			'--bg-hover': '#3f3835',
			'--text-primary': '#e7e0db',
			'--text-secondary': '#a8a09b',
			'--text-muted': '#78716c',
			'--border': '#44403c',
			'--border-subtle': '#3a3634',
			'--accent': '#f59e0b',
			'--accent-muted': '#b87308',
			'--trust-direct': '#34d399',
			'--trust-2hop': '#fbbf24',
			'--trust-3hop': '#fb923c',
			'--trust-untrusted': '#78716c',
			'--link': '#f59e0b',
			'--link-hover': '#fbbf24',
			'--danger': '#ef4444',
			'--success': '#34d399'
		}
	},
	{
		id: 'stone',
		name: 'Stone',
		vars: {
			'--bg': '#f5f5f4',
			'--bg-surface': '#ffffff',
			'--bg-surface-dim': '#fafaf9',
			'--bg-surface-raised': '#e7e5e4',
			'--bg-hover': '#d6d3d1',
			'--text-primary': '#1c1917',
			'--text-secondary': '#57534e',
			'--text-muted': '#a8a29e',
			'--border': '#d6d3d1',
			'--border-subtle': '#e7e5e4',
			'--accent': '#7c3aed',
			'--accent-muted': '#6d28d9',
			'--trust-direct': '#0d9488',
			'--trust-2hop': '#d97706',
			'--trust-3hop': '#dc2626',
			'--trust-untrusted': '#a8a29e',
			'--link': '#7c3aed',
			'--link-hover': '#1c1917',
			'--danger': '#dc2626',
			'--success': '#0d9488'
		}
	},
	{
		id: 'moss',
		name: 'Moss',
		vars: {
			'--bg': '#e8efe4',
			'--bg-surface': '#f2f7ef',
			'--bg-surface-dim': '#edf3ea',
			'--bg-surface-raised': '#d5e0cf',
			'--bg-hover': '#c4d4bc',
			'--text-primary': '#1a2618',
			'--text-secondary': '#4a5d46',
			'--text-muted': '#869880',
			'--border': '#b8ccb0',
			'--border-subtle': '#d5e0cf',
			'--accent': '#2d6a4f',
			'--accent-muted': '#1b4332',
			'--trust-direct': '#0077b6',
			'--trust-2hop': '#e36414',
			'--trust-3hop': '#ae2012',
			'--trust-untrusted': '#869880',
			'--link': '#2d6a4f',
			'--link-hover': '#1a2618',
			'--danger': '#ae2012',
			'--success': '#0077b6'
		}
	},
	{
		id: 'coral',
		name: 'Coral',
		vars: {
			'--bg': '#fff1ee',
			'--bg-surface': '#fff8f6',
			'--bg-surface-dim': '#fff4f2',
			'--bg-surface-raised': '#fdddd6',
			'--bg-hover': '#f9c4b8',
			'--text-primary': '#2d1610',
			'--text-secondary': '#6b3a2e',
			'--text-muted': '#b08878',
			'--border': '#e8bfb3',
			'--border-subtle': '#f5d8d0',
			'--accent': '#c2410c',
			'--accent-muted': '#9a3412',
			'--trust-direct': '#1d4ed8',
			'--trust-2hop': '#7e22ce',
			'--trust-3hop': '#be123c',
			'--trust-untrusted': '#b08878',
			'--link': '#c2410c',
			'--link-hover': '#2d1610',
			'--danger': '#be123c',
			'--success': '#1d4ed8'
		}
	},
	{
		id: 'blueprint',
		name: 'Blueprint',
		vars: {
			'--bg': '#dce8f5',
			'--bg-surface': '#e8f0fa',
			'--bg-surface-dim': '#e2ecf8',
			'--bg-surface-raised': '#c5d7ec',
			'--bg-hover': '#afc8e2',
			'--text-primary': '#0c1929',
			'--text-secondary': '#2e4a6b',
			'--text-muted': '#7090b0',
			'--border': '#a3bdd8',
			'--border-subtle': '#c5d7ec',
			'--accent': '#1d4ed8',
			'--accent-muted': '#1e3a8a',
			'--trust-direct': '#0f766e',
			'--trust-2hop': '#b45309',
			'--trust-3hop': '#be123c',
			'--trust-untrusted': '#7090b0',
			'--link': '#1d4ed8',
			'--link-hover': '#0c1929',
			'--danger': '#be123c',
			'--success': '#0f766e'
		}
	}
];

export const DEFAULT_THEME: ThemeId = 'rose-pine';

export function getTheme(id: ThemeId): ThemeMeta {
	return themes.find((t) => t.id === id) ?? themes[0];
}

export function applyTheme(id: ThemeId): void {
	if (typeof document === 'undefined') return;
	const theme = getTheme(id);
	const root = document.documentElement;
	for (const [prop, value] of Object.entries(theme.vars)) {
		root.style.setProperty(prop, value);
	}
}
