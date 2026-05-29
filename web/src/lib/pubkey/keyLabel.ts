/**
 * Human-recognizable "name tag" for an Ed25519 public key.
 *
 * Works for any key hex — instance signing keys, user credential keys, etc.
 * This is a *recognition* aid only: a glanceable glyph + two-word name to spot
 * "that's the key I think it is" at a glance. It is deliberately low-entropy
 * and MUST NOT be treated as identity verification — the full key hex (or its
 * grouped fingerprint) remains the only thing to compare when actually
 * confirming identity. An attacker can grind a key to collide a short label,
 * but cannot collide the full key shown alongside it.
 *
 * The label is a pure, deterministic function of the lowercase key hex. We
 * derive it from a hash of the key rather than slicing raw key bytes so the
 * display scheme can change later without it looking like the key changed, and
 * so the visible label is never a literal prefix of the key material.
 */

// Curated "cozy cottagecore" wordlists: warm/homey adjectives + snug objects
// and small critters. Chosen for memorability — a slightly incongruous concrete
// image ("Buttery Hedgehog") sticks far better than a generic one. Every
// adjective×noun pairing is screened to stay wholesome, since the label is
// shown for *someone else's* key. Lengths need not be powers of two (indices
// are taken modulo length), so these can grow freely.
const ADJECTIVES = [
	'toasty', 'mossy', 'plump', 'buttery', 'cosy', 'downy', 'snug', 'honeyed',
	'woolly', 'fuzzy', 'cinnamon', 'ginger', 'maple', 'custard', 'caramel', 'hazel',
	'amber', 'golden', 'dappled', 'drowsy', 'sunlit', 'mellow', 'gentle', 'tender',
	'doughy', 'crumbly', 'toasted', 'spiced', 'nutmeg', 'clover', 'heather', 'briar',
	'ferny', 'leafy', 'rosy', 'dewy', 'misty', 'plush', 'cushy', 'comfy',
	'humble', 'quiet', 'calm', 'dozy', 'lazy', 'sleepy', 'wistful', 'cheery',
	'jolly', 'merry', 'snuggly', 'puffy', 'fluffy', 'squishy', 'pillowy', 'creamy',
	'sugary', 'vanilla', 'minty', 'peachy', 'cocoa', 'oaty', 'wholesome', 'cuddly',
	'velvety', 'silky', 'satiny', 'flannel', 'knitted', 'quilted', 'padded', 'balmy',
	'glowing', 'homespun', 'rustic', 'hearthside', 'candlelit', 'snowy', 'frosted', 'wispy',
	'breezy', 'sunny', 'garden', 'meadow', 'willow', 'birch', 'cedar', 'pine',
	'oaken', 'berry', 'plum', 'cherry', 'apricot', 'almond', 'toffee', 'fudgy',
	'jammy', 'syrupy', 'cider', 'spongy', 'marbled', 'dusted', 'powdered', 'frothy',
	'whipped', 'milky', 'warmed', 'ruddy', 'russet', 'ochre', 'copper', 'bronzed',
	'sandy', 'oatmeal', 'wheaten', 'barley', 'brambly', 'blossomy', 'floral', 'fragrant',
	'herby', 'lavender', 'chamomile', 'primrose', 'twilit', 'starlit', 'moonlit', 'firelit'
];

const NOUNS = [
	'teapot', 'lantern', 'acorn', 'mushroom', 'dormouse', 'hedgehog', 'kettle', 'quilt',
	'mitten', 'blanket', 'pillow', 'cushion', 'candle', 'cottage', 'biscuit', 'muffin',
	'crumpet', 'scone', 'pancake', 'waffle', 'dumpling', 'pudding', 'cupcake', 'marshmallow',
	'pretzel', 'bagel', 'honeypot', 'jampot', 'teacup', 'saucer', 'thimble', 'slipper',
	'sweater', 'cardigan', 'scarf', 'beanie', 'hamster', 'fieldmouse', 'chipmunk', 'squirrel',
	'bunny', 'duckling', 'gosling', 'piglet', 'lamb', 'fawn', 'kitten', 'puppy',
	'ladybug', 'firefly', 'bumblebee', 'caterpillar', 'snail', 'toadstool', 'pinecone', 'chestnut',
	'hazelnut', 'walnut', 'pumpkin', 'turnip', 'radish', 'parsnip', 'hearth', 'nook',
	'armchair', 'footstool', 'hammock', 'bookcase', 'fireplace', 'chimney', 'windowsill', 'doorstep',
	'gazebo', 'greenhouse', 'birdhouse', 'birdbath', 'beehive', 'henhouse', 'barn', 'haystack',
	'wheelbarrow', 'trowel', 'basket', 'hamper', 'teacozy', 'doily', 'napkin', 'tablecloth',
	'apron', 'stockpot', 'saucepan', 'ladle', 'whisk', 'rollingpin', 'mug', 'pitcher',
	'crock', 'churn', 'loaf', 'sourdough', 'shortbread', 'gingerbread', 'flapjack', 'oatcake',
	'tealeaf', 'honeycomb', 'tart', 'pie', 'cobbler', 'trifle', 'eclair', 'macaron',
	'truffle', 'fudge', 'marzipan', 'gingersnap', 'porridge', 'muesli', 'conker', 'newt',
	'frog', 'cricket', 'moth', 'beetle', 'starling', 'robin', 'wren', 'sparrow'
];

/** Identicon grid edge length. Columns are mirrored for a symmetric glyph. */
export const GRID = 5;

export interface KeyLabel {
	/** Two-word recognizable name, e.g. "Brave Otter". */
	name: string;
	adjective: string;
	noun: string;
	/** Foreground hue in degrees [0, 360) for the glyph. */
	hue: number;
	/** Row-major GRID*GRID booleans; true cells are painted. Left-right mirrored. */
	cells: boolean[];
}

/**
 * 32-bit FNV-1a over a string, prefixed with a one-byte salt so distinct
 * salts yield decorrelated values. Non-cryptographic; for display only.
 */
function fnv1a(s: string, salt: number): number {
	let h = 0x811c9dc5;
	h ^= salt & 0xff;
	h = Math.imul(h, 0x01000193);
	for (let i = 0; i < s.length; i++) {
		h ^= s.charCodeAt(i);
		h = Math.imul(h, 0x01000193);
	}
	return h >>> 0;
}

/**
 * Deterministic xorshift128 stream seeded from four salted hashes of the key
 * (128 bits of state). The wide state matters: it means the label's
 * distinctness is bounded by the bits we actually render (~37: 14 words +
 * ~8.5 hue + 15 identicon), not by the seed. A 32-bit seed would have silently
 * capped distinctness at 32 bits no matter how much we drew.
 */
function makeRng(hex: string): () => number {
	let x = fnv1a(hex, 1) || 1; // guard: xorshift128 must not start all-zero
	let y = fnv1a(hex, 2);
	let z = fnv1a(hex, 3);
	let w = fnv1a(hex, 4);
	return () => {
		const t = (x ^ (x << 11)) >>> 0;
		x = y;
		y = z;
		z = w;
		w = (w ^ (w >>> 19) ^ (t ^ (t >>> 8))) >>> 0;
		return w;
	};
}

const capitalize = (w: string) => w.charAt(0).toUpperCase() + w.slice(1);

/** Derive the recognition label for a key from its lowercase hex string. */
export function keyLabel(pubkeyHex: string): KeyLabel {
	const next = makeRng(pubkeyHex.toLowerCase());

	const adjective = ADJECTIVES[next() % ADJECTIVES.length];
	const noun = NOUNS[next() % NOUNS.length];
	const hue = next() % 360;

	const cells = new Array<boolean>(GRID * GRID).fill(false);
	const half = Math.ceil(GRID / 2); // mirror left half (incl. center column)
	for (let row = 0; row < GRID; row++) {
		for (let col = 0; col < half; col++) {
			const on = (next() & 1) === 1;
			cells[row * GRID + col] = on;
			cells[row * GRID + (GRID - 1 - col)] = on;
		}
	}

	return { name: `${capitalize(adjective)} ${capitalize(noun)}`, adjective, noun, hue, cells };
}
