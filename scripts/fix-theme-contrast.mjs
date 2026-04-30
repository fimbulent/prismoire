#!/usr/bin/env node
// Auto-fix theme contrast issues using a unified greedy "common offender"
// loop. At each step, we identify the slot whose adjustment yields the
// largest net reduction in GLOBAL in-scope failure count with the smallest
// perceptual deviation (in OKLab), apply that fix, and repeat until no
// slot can resolve any further failure.
//
// This naturally favors single bg-slot moves that cover many text/bg pairs
// over adjusting each fg slot individually.
//
// In scope:
//   - High-priority body slots (text-primary, text-secondary, link, link-hover,
//     danger, success): need ≥ 4.5:1 on every bg slot.
//   - High-priority UI slot (accent): needs ≥ 3:1 on every bg slot.
//   - text-muted whose contrast is < 3:1: bring it up to 3:1
//     (de-emphasized text gets the WCAG large-text threshold, not body 4.5).
//   - On bg-hover only: accent-muted + trust-* slots need ≥ 3:1
//     (hover is interactive feedback, must stay legible).
//
// Skipped: `border` (decorative 1px borders aren't subject to WCAG 1.4.11).
//
// Strategy:
//   1. At each iteration, compute current failures and the set of slots
//      they reference (as fg or bg).
//   2. For each candidate slot, search (dir × chromaScale × ΔL) for the
//      configuration that maximises net global failure reduction while
//      respecting visual-ordering constraints.
//   3. Pick the slot with the highest resolved count; tiebreak by the
//      smallest perceptual deviation (ΔL plus a chroma-loss penalty).
//   4. Apply the best fix to a working copy of the theme tokens; loop until
//      no candidate resolves any failure.
//
// Constraints:
//   - BG slots must keep their dim → bright ordering, with ≥ BG_GAP OKLab L
//     between any two adjacent slots after the fix.
//   - The text triplet (text-muted < text-secondary < text-primary by
//     visibility, polarity-aware) must keep ≥ TEXT_ORDER_GAP between
//     adjacent slots after the fix.
//   - FG slots may desaturate (chroma reduction) when pure L can't hit
//     threshold without gamut clipping (e.g. saturated reds on light bgs).
//
// Usage: `just theme-contrast` (dry run) | `just theme-contrast-apply`
//   or:  `node scripts/fix-theme-contrast.mjs [--apply]`

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CSS_PATH = resolve(__dirname, '..', 'web', 'src', 'app.css');
const APPLY = process.argv.includes('--apply');

// ---------- Color math ----------

const hexToRgb = (h) => {
	const n = parseInt(h.slice(1), 16);
	return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
};
const rgbToHex = ([r, g, b]) =>
	'#' +
	[r, g, b]
		.map((v) => Math.max(0, Math.min(255, Math.round(v))).toString(16).padStart(2, '0'))
		.join('');
const srgbToLinear = (c) => {
	const v = c / 255;
	return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
};
const linearToSrgb = (v) => {
	v = Math.max(0, Math.min(1, v));
	const c = v <= 0.0031308 ? v * 12.92 : 1.055 * Math.pow(v, 1 / 2.4) - 0.055;
	return c * 255;
};
const luma = ([r, g, b]) =>
	0.2126 * srgbToLinear(r) + 0.7152 * srgbToLinear(g) + 0.0722 * srgbToLinear(b);
const contrast = (h1, h2) => {
	const l1 = luma(hexToRgb(h1));
	const l2 = luma(hexToRgb(h2));
	const [a, b] = l1 > l2 ? [l1, l2] : [l2, l1];
	return (a + 0.05) / (b + 0.05);
};

function rgbToOklab([r, g, b]) {
	const lr = srgbToLinear(r),
		lg = srgbToLinear(g),
		lb = srgbToLinear(b);
	const l = 0.4122214708 * lr + 0.5363325363 * lg + 0.0514459929 * lb;
	const m = 0.2119034982 * lr + 0.6806995451 * lg + 0.1073969566 * lb;
	const s = 0.0883024619 * lr + 0.2817188376 * lg + 0.6299787005 * lb;
	const l_ = Math.cbrt(l),
		m_ = Math.cbrt(m),
		s_ = Math.cbrt(s);
	return [
		0.2104542553 * l_ + 0.793617785 * m_ - 0.0040720468 * s_,
		1.9779984951 * l_ - 2.428592205 * m_ + 0.4505937099 * s_,
		0.0259040371 * l_ + 0.7827717662 * m_ - 0.808675766 * s_,
	];
}

function oklabToRgb([L, a, b]) {
	const l_ = L + 0.3963377774 * a + 0.2158037573 * b;
	const m_ = L - 0.1055613458 * a - 0.0638541728 * b;
	const s_ = L - 0.0894841775 * a - 1.291485548 * b;
	const l = l_ * l_ * l_,
		m = m_ * m_ * m_,
		s = s_ * s_ * s_;
	return [
		linearToSrgb(+4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s),
		linearToSrgb(-1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s),
		linearToSrgb(-0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s),
	];
}

// Adjust both lightness and chroma. Some saturated colors (e.g. gruvbox-dark
// `danger` #fb4934) cannot reach high enough luminance on a light bg without
// gamut-clipping back below threshold; reducing chroma frees the gamut so L
// can climb further. `chromaScale=1.0` preserves saturation; lower values
// desaturate.
function adjustLC(hex, deltaL, chromaScale) {
	const [L, a, b] = rgbToOklab(hexToRgb(hex));
	const newL = Math.max(0, Math.min(1, L + deltaL));
	return rgbToHex(oklabToRgb([newL, a * chromaScale, b * chromaScale]));
}

const oklabL = (hex) => rgbToOklab(hexToRgb(hex))[0];

function oklabDist(h1, h2) {
	const [L1, a1, b1] = rgbToOklab(hexToRgb(h1));
	const [L2, a2, b2] = rgbToOklab(hexToRgb(h2));
	const dL = L1 - L2,
		da = a1 - a2,
		db = b1 - b2;
	return Math.sqrt(dL * dL + da * da + db * db);
}

// ---------- Theme parsing ----------

const css = readFileSync(CSS_PATH, 'utf8');

function extractThemes(srcCss) {
	const themes = {};
	const re = /\[data-theme='([^']+)'\]\s*\{([^}]+)\}/g;
	let m;
	while ((m = re.exec(srcCss)) !== null) {
		const tokens = {};
		const tre = /--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})/g;
		let t;
		while ((t = tre.exec(m[2])) !== null) tokens[t[1]] = t[2].toLowerCase();
		themes[m[1]] = tokens;
	}
	return themes;
}

// ---------- Failure detection (in-scope only) ----------

const BG_SLOTS = ['bg', 'bg-surface-dim', 'bg-surface', 'bg-surface-raised', 'bg-hover'];
const HIGH_PRIO_BODY = new Set([
	'text-primary',
	'text-secondary',
	'link',
	'link-hover',
	'danger',
	'success',
]);
const HIGH_PRIO_UI = new Set(['accent']);
const ALL_BODY = new Set([
	'text-primary',
	'text-secondary',
	'text-muted',
	'link',
	'link-hover',
	'danger',
	'success',
]);
const HOVER_UI = new Set([
	'accent-muted',
	'trust-direct',
	'trust-2hop',
	'trust-3hop',
	'trust-untrusted',
]);

function inScope(fg, bg, ratio) {
	if (HIGH_PRIO_BODY.has(fg)) return { threshold: 4.5, kind: 'body' };
	if (HIGH_PRIO_UI.has(fg)) return { threshold: 3.0, kind: 'ui' };
	// text-muted only triggers when catastrophic; needs only WCAG large-text 3:1.
	if (fg === 'text-muted' && ratio < 3.0) return { threshold: 3.0, kind: 'body' };
	if (bg === 'bg-hover' && HOVER_UI.has(fg)) return { threshold: 3.0, kind: 'ui' };
	return null;
}

function findFailures(tokens) {
	const fails = [];
	const allFgs = new Set([...ALL_BODY, ...HOVER_UI, ...HIGH_PRIO_UI]);
	for (const fg of allFgs) {
		if (!tokens[fg]) continue;
		for (const bg of BG_SLOTS) {
			if (!tokens[bg]) continue;
			const r = contrast(tokens[fg], tokens[bg]);
			const scope = inScope(fg, bg, r);
			if (!scope) continue;
			if (r < scope.threshold) {
				fails.push({
					fg,
					bg,
					fgHex: tokens[fg],
					bgHex: tokens[bg],
					ratio: r,
					threshold: scope.threshold,
				});
			}
		}
	}
	return fails;
}

// ---------- Tunables ----------

// Min OKLab L gap between adjacent bg slots after a bg fix. ΔE between two
// chroma-matched colors collapses to |ΔL|, so 0.025 was too tight in
// practice (let bg-surface-raised land within JND of bg-hover). 0.04 keeps
// the surface gradient clearly distinguishable.
const BG_GAP = 0.04;

// Min OKLab L gap between adjacent text-triplet slots (text-muted vs
// text-secondary vs text-primary). 0.075 is enough to remain perceptible
// even when neighbouring slots share chroma (where ΔE is dominated by ΔL).
const TEXT_ORDER_GAP = 0.075;

// Chroma reduction fallback: try full saturation first, then desaturate
// progressively for FG slots whose target L is unreachable at full chroma
// (gamut clipping). BG slots never desaturate.
const CHROMA_STEPS = [1.0, 0.85, 0.7, 0.55, 0.4, 0.25, 0.1];

// Search resolution for ΔL within [0, MAX_DELTA]. 80 steps × 0.5 = 0.00625
// per step in OKLab L — fine enough to find near-minimum fixes.
const STEPS = 80;
const MAX_DELTA = 0.5;

// ---------- Bounds for a slot's allowable post-fix L ----------

// Determine theme polarity: in a dark theme, text-primary L > bg L → +1
// (more-visible means lighter); in a light theme, opposite → -1.
function visibilityDirection(tokens) {
	if (!tokens['text-primary'] || !tokens['bg']) return +1;
	return oklabL(tokens['text-primary']) > oklabL(tokens['bg']) ? +1 : -1;
}

// BG slot bounds: keep BG_GAP from each immediate neighbour in the
// dim → bright ordering, derived from the current workingTokens snapshot.
function bgBounds(slot, workingTokens) {
	const ordered = BG_SLOTS.filter((s) => workingTokens[s])
		.map((s) => ({ slot: s, L: oklabL(workingTokens[s]) }))
		.sort((a, b) => a.L - b.L);
	const idx = ordered.findIndex((x) => x.slot === slot);
	return {
		minLabL: idx > 0 ? ordered[idx - 1].L + BG_GAP : -Infinity,
		maxLabL: idx < ordered.length - 1 ? ordered[idx + 1].L - BG_GAP : Infinity,
	};
}

// FG ordering bounds: text-muted < text-secondary < text-primary in
// visibility, with TEXT_ORDER_GAP between them. Polarity-aware: in dark
// themes "more visible" = higher L; in light themes = lower L. Bounds use
// the current workingTokens L for each neighbour (already-fixed slots
// contribute their post-fix L automatically). Non-text slots: no bounds.
function fgOrderingBounds(slot, workingTokens) {
	const TEXT_ORDER = ['text-muted', 'text-secondary', 'text-primary'];
	const idx = TEXT_ORDER.indexOf(slot);
	if (idx < 0) return { minLabL: -Infinity, maxLabL: Infinity };
	const dir = visibilityDirection(workingTokens);
	let minLabL = -Infinity;
	let maxLabL = Infinity;
	const dimmer = TEXT_ORDER[idx - 1];
	const brighter = TEXT_ORDER[idx + 1];
	if (dimmer && workingTokens[dimmer]) {
		const oL = oklabL(workingTokens[dimmer]);
		if (dir > 0) minLabL = Math.max(minLabL, oL + TEXT_ORDER_GAP);
		else maxLabL = Math.min(maxLabL, oL - TEXT_ORDER_GAP);
	}
	if (brighter && workingTokens[brighter]) {
		const oL = oklabL(workingTokens[brighter]);
		if (dir > 0) maxLabL = Math.min(maxLabL, oL - TEXT_ORDER_GAP);
		else minLabL = Math.max(minLabL, oL + TEXT_ORDER_GAP);
	}
	return { minLabL, maxLabL };
}

// ---------- Best fix for a single slot (BG or FG, unified) ----------
//
// Iterates over (direction, chromaScale, delta) and finds the configuration
// that maximises GLOBAL net failure-count reduction. Tiebreak: smallest
// perceptual deviation (ΔL plus a chroma-loss penalty so pure-L fixes are
// preferred over desaturating ones). BG slots only iterate chromaScale=1.0
// (we never desaturate the surface gradient). Returns null if no
// configuration resolves at least one failure.

function computeFixForSlot(slot, workingTokens, currentFailCount) {
	const isBg = BG_SLOTS.includes(slot);
	const hex = workingTokens[slot];
	if (!hex) return null;
	const [origL, origA, origB] = rgbToOklab(hexToRgb(hex));

	const bounds = isBg ? bgBounds(slot, workingTokens) : fgOrderingBounds(slot, workingTokens);
	const chromaSteps = isBg ? [1.0] : CHROMA_STEPS;

	let best = null;
	for (const dir of [+1, -1]) {
		for (const chromaScale of chromaSteps) {
			for (let i = 1; i <= STEPS; i++) {
				const d = (i / STEPS) * MAX_DELTA;
				const newL = origL + dir * d;
				if (newL < bounds.minLabL || newL > bounds.maxLabL) continue;
				const newHex = isBg
					? rgbToHex(oklabToRgb([newL, origA, origB]))
					: adjustLC(hex, dir * d, chromaScale);
				if (newHex === hex) continue;
				const trial = { ...workingTokens, [slot]: newHex };
				// Net global resolution: positive iff this fix removes more
				// failures than it introduces. Counting globally (rather than
				// only on the current slot) correctly penalises moves that
				// fix N pairs while breaking M others.
				const resolved = currentFailCount - findFailures(trial).length;
				if (resolved < 1) continue;
				const dev = d + (1 - chromaScale) * 0.5;
				if (
					!best ||
					resolved > best.resolved ||
					(resolved === best.resolved && dev < best.dev)
				) {
					best = {
						resolved,
						dev,
						newHex,
						delta: d,
						dir,
						chromaScale,
						newLabL: newL,
					};
				}
			}
		}
	}
	return best;
}

// ---------- Reason string ----------

function buildReason(slot, fix, slotFails, isBg) {
	const verb = fix.dir > 0 ? 'lightened' : 'darkened';
	if (slotFails.length === 0) {
		return `${verb} (incidental, resolved ${fix.resolved} via knock-on)`;
	}
	const worst = slotFails.reduce((a, b) => (a.ratio < b.ratio ? a : b));
	const chromaNote = fix.chromaScale < 1 ? `, desat ×${fix.chromaScale.toFixed(2)}` : '';
	if (isBg) {
		return `${verb} to resolve ${fix.resolved} pair(s) on ${slot} (worst was ${worst.fg} at ${worst.ratio.toFixed(2)}, need ${worst.threshold})`;
	}
	const target = slotFails.length > 1 ? `${slotFails.length} bg slots` : worst.bg;
	return `${verb} for ${worst.threshold}:1 on ${target} (was ${worst.ratio.toFixed(2)}${chromaNote})`;
}

// ---------- Apply changes to CSS in-place ----------

function applyChanges(srcCss, themeId, changes) {
	const blockRe = new RegExp(`(\\[data-theme='${themeId}'\\]\\s*\\{)([^}]+)(\\})`);
	let replaced = false;
	const out = srcCss.replace(blockRe, (_, open, body, close) => {
		replaced = true;
		let newBody = body;
		for (const c of changes) {
			// Match the variable line and any pre-existing trailing /* comment */
			const tokenRe = new RegExp(
				`(\\n[ \\t]*)--${c.token}:\\s*${c.oldHex};(?:[ \\t]*/\\*[^*]*\\*+(?:[^/*][^*]*\\*+)*/)?`,
				'i',
			);
			const before = newBody;
			newBody = newBody.replace(tokenRe, (_m, indent) => {
				return `${indent}--${c.token}: ${c.newHex}; /* was ${c.oldHex}: ${c.reason} */`;
			});
			if (newBody === before) {
				console.error(`  ! could not locate --${c.token}: ${c.oldHex} in ${themeId}`);
			}
		}
		return open + newBody + close;
	});
	if (!replaced) console.error(`  ! could not locate theme block ${themeId}`);
	return out;
}

// ---------- Main: per-theme greedy loop ----------

const themes = extractThemes(css);
let updatedCss = css;
const report = [];

for (const [id, tokens] of Object.entries(themes)) {
	const initialFails = findFailures(tokens);
	if (initialFails.length === 0) {
		report.push({ theme: id, changes: [] });
		continue;
	}

	// Working copy of tokens — mutated as we apply each greedy fix.
	const workingTokens = { ...tokens };
	// Per-iteration log; consolidated by token before being recorded /
	// applied so the same slot adjusted twice yields a single CSS edit.
	const iterLog = [];

	while (true) {
		const failures = findFailures(workingTokens);
		if (failures.length === 0) break;

		// Slots referenced by any current failure (as fg or bg) are the
		// only slots whose adjustment can change failure count.
		const slotsToTry = new Set();
		for (const f of failures) {
			slotsToTry.add(f.fg);
			slotsToTry.add(f.bg);
		}

		let best = null;
		for (const slot of slotsToTry) {
			const fix = computeFixForSlot(slot, workingTokens, failures.length);
			if (!fix) continue;
			if (
				!best ||
				fix.resolved > best.fix.resolved ||
				(fix.resolved === best.fix.resolved && fix.dev < best.fix.dev)
			) {
				best = { slot, fix };
			}
		}
		if (!best) break;

		const isBg = BG_SLOTS.includes(best.slot);
		const slotFails = failures.filter((f) =>
			isBg ? f.bg === best.slot : f.fg === best.slot,
		);

		iterLog.push({
			token: best.slot,
			fromHex: workingTokens[best.slot],
			newHex: best.fix.newHex,
			delta: best.fix.delta,
			reason: buildReason(best.slot, best.fix, slotFails, isBg),
			fixedCount: best.fix.resolved,
		});
		workingTokens[best.slot] = best.fix.newHex;
	}

	// Consolidate per-token: applyChanges needs the ORIGINAL hex (from
	// `tokens`) to locate the line in source CSS. If a token was adjusted
	// across multiple iterations, we keep the first oldHex, take the
	// final newHex, and merge reasons.
	const byToken = new Map();
	for (const e of iterLog) {
		if (byToken.has(e.token)) {
			const prev = byToken.get(e.token);
			prev.newHex = e.newHex;
			prev.delta += e.delta;
			prev.fixedCount += e.fixedCount;
			prev.reason = `${prev.reason}; then ${e.reason}`;
		} else {
			byToken.set(e.token, {
				token: e.token,
				oldHex: tokens[e.token],
				newHex: e.newHex,
				delta: e.delta,
				reason: e.reason,
				fixedCount: e.fixedCount,
			});
		}
	}
	const changes = [...byToken.values()];

	if (changes.length > 0) {
		updatedCss = applyChanges(updatedCss, id, changes);
	}
	report.push({ theme: id, changes });
}

// Re-audit after changes
const themesAfter = extractThemes(updatedCss);
const remaining = {};
for (const [id, tokens] of Object.entries(themesAfter)) {
	const fails = findFailures(tokens);
	if (fails.length > 0) remaining[id] = fails;
}

// ---------- Report ----------

console.log('# Contrast fix plan\n');
let totalChanges = 0;
let touchedThemes = 0;
for (const r of report) {
	if (r.changes.length === 0) continue;
	touchedThemes++;
	console.log(`## ${r.theme}\n`);
	console.log('| Token | Old | New | ΔL | Fixes | Reason |');
	console.log('|-------|-----|-----|-----|-------|--------|');
	for (const c of r.changes) {
		totalChanges++;
		console.log(
			`| ${c.token} | \`${c.oldHex}\` | \`${c.newHex}\` | ${c.delta.toFixed(3)} | ${c.fixedCount} | ${c.reason} |`,
		);
	}
	console.log();
}

console.log('---');
console.log(`**Total token changes:** ${totalChanges} across ${touchedThemes} themes.\n`);

const remainingCount = Object.values(remaining).reduce((s, fs) => s + fs.length, 0);
if (remainingCount === 0) {
	console.log('**All in-scope failures resolved.** ✓');
} else {
	console.log(`**Remaining in-scope failures:** ${remainingCount}`);
	for (const [id, fs] of Object.entries(remaining)) {
		console.log(`- ${id}: ${fs.length}`);
		for (const f of fs.slice(0, 5)) {
			console.log(
				`  - ${f.fg} \`${f.fgHex}\` on ${f.bg} \`${f.bgHex}\` → ${f.ratio.toFixed(2)}:1 (need ${f.threshold}:1)`,
			);
		}
	}
}

// ---------- Post-fix sanity check ----------
//
// Flag any pair of slots within the same theme whose post-fix colors are
// perceptually too close (OKLab distance < threshold). Bg slots and text
// slots are checked within their own groups; semantic colors (link, danger,
// success, accent) are also checked against text slots since they're often
// rendered as inline body text. trust-* are checked against each other
// (the gradient should remain readable as 4 distinct steps).

const TEXT_GROUP = ['text-primary', 'text-secondary', 'text-muted'];
const BG_GROUP = BG_SLOTS;
const SEMANTIC_GROUP = ['accent', 'link', 'link-hover', 'danger', 'success'];
const TRUST_GROUP = ['trust-direct', 'trust-2hop', 'trust-3hop', 'trust-untrusted'];

// Threshold below which two slots are perceptually too close to distinguish.
// 0.04 is roughly "just-noticeable difference" in OKLab; 0.025 is borderline.
const COLLISION_DIST = 0.04;

console.log('\n# Post-fix sanity check\n');
console.log(
	`Flags pairs whose post-fix OKLab distance is < ${COLLISION_DIST} **and** got closer than they were before. Pre-existing close pairs (e.g. native bg-slot gradations) and the intentional \`link-hover ≡ text-primary\` convention are excluded.\n`,
);
const issues = [];
for (const [id, tokens] of Object.entries(themesAfter)) {
	const orig = themes[id];
	const checks = [
		{ group: TEXT_GROUP, label: 'text' },
		{ group: BG_GROUP, label: 'bg' },
		{ group: TRUST_GROUP, label: 'trust gradient' },
	];
	const flag = (kind, a, b) => {
		if (!tokens[a] || !tokens[b]) return;
		const dPost = oklabDist(tokens[a], tokens[b]);
		if (dPost >= COLLISION_DIST) return;
		const dPre = orig[a] && orig[b] ? oklabDist(orig[a], orig[b]) : Infinity;
		// Only flag if our changes made it closer than it was originally.
		if (dPost >= dPre - 0.001) return;
		issues.push({ theme: id, kind, a, b, aHex: tokens[a], bHex: tokens[b], dPost, dPre });
	};
	for (const { group, label } of checks) {
		for (let i = 0; i < group.length; i++) {
			for (let j = i + 1; j < group.length; j++) {
				flag(label, group[i], group[j]);
			}
		}
	}
	// link-hover ≡ text-primary is an intentional convention in many themes
	// (hover transitions a link to body-text colour) — exclude that pair only.
	for (const s of SEMANTIC_GROUP) {
		if (s === 'link-hover') continue;
		flag('semantic-vs-text', s, 'text-primary');
	}
}

if (issues.length === 0) {
	console.log('No newly-introduced collisions. ✓');
} else {
	console.log(`${issues.length} newly-introduced close pair(s):\n`);
	console.log('| Theme | Group | Slot A | Slot B | A hex | B hex | ΔE post | ΔE pre |');
	console.log('|-------|-------|--------|--------|-------|-------|---------|--------|');
	for (const i of issues) {
		const dPreStr = isFinite(i.dPre) ? i.dPre.toFixed(3) : '—';
		console.log(
			`| ${i.theme} | ${i.kind} | ${i.a} | ${i.b} | \`${i.aHex}\` | \`${i.bHex}\` | ${i.dPost.toFixed(3)} | ${dPreStr} |`,
		);
	}
}

if (APPLY) {
	writeFileSync(CSS_PATH, updatedCss);
	console.log('\n✓ Written to app.css');
} else {
	console.log('\n(dry run — pass --apply to write changes)');
}
