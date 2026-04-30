-- Add a per-user prose-font preference. Mirrors the `theme` column:
-- the picker in `web/src/routes/settings/+page.svelte` lets users
-- choose among a small allow-list of self-hosted families served from
-- `web/static/fonts/`. The font only applies to rendered prose
-- (Markdown post bodies); UI chrome continues to use the system stack.
ALTER TABLE user_settings ADD COLUMN font TEXT NOT NULL DEFAULT 'inter';
