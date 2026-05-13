-- Update the default theme to 'rose-pine-moon' and default prose font
-- to 'literata'. Several themes (Tokyo Night family, Catppuccin family)
-- and prose fonts (Inter, Source Sans 3, Source Serif 4) were removed
-- from the picker; any existing rows still pointing at one of those
-- values are reset to the new default so the SSR'd `data-theme` /
-- `data-font` attribute always resolves to a known palette/font block
-- in `web/src/app.css`.
--
-- SQLite has no `ALTER COLUMN DEFAULT`, so we rebuild the table. No
-- other table FK-references `user_settings`, so a straight rebuild
-- (rather than the full leaves-to-root dance) is sufficient.

CREATE TABLE user_settings_new (
    user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id),
    theme TEXT NOT NULL DEFAULT 'rose-pine-moon',
    font TEXT NOT NULL DEFAULT 'literata'
);

INSERT INTO user_settings_new (user_id, theme, font)
SELECT
    user_id,
    CASE
        WHEN theme IN (
            'tokyo-night', 'tokyo-night-storm', 'tokyo-night-day',
            'catppuccin-mocha', 'catppuccin-macchiato',
            'catppuccin-frappe', 'catppuccin-latte'
        ) THEN 'rose-pine-moon'
        ELSE theme
    END,
    CASE
        WHEN font IN ('inter', 'source-sans-3', 'source-serif-4') THEN 'literata'
        ELSE font
    END
FROM user_settings;

DROP TABLE user_settings;
ALTER TABLE user_settings_new RENAME TO user_settings;
