-- Switch the default theme from 'rose-pine-moon' to 'rose-pine'. Both
-- palettes are still in the picker — only the *default* applied to
-- users who have never opened the settings page changes. Existing
-- explicit choices in `user_settings` are preserved.
--
-- SQLite has no `ALTER COLUMN DEFAULT`, so we rebuild the table. No
-- other table FK-references `user_settings`, so a straight rebuild
-- (rather than the full leaves-to-root dance) is sufficient.

CREATE TABLE user_settings_new (
    user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id),
    theme TEXT NOT NULL DEFAULT 'rose-pine',
    font TEXT NOT NULL DEFAULT 'literata'
);

INSERT INTO user_settings_new (user_id, theme, font)
SELECT user_id, theme, font FROM user_settings;

DROP TABLE user_settings;
ALTER TABLE user_settings_new RENAME TO user_settings;
