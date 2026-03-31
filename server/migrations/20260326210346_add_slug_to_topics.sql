-- Add a slug column for URL routing and uniqueness enforcement.
-- The slug is the lowercased name with spaces and hyphens replaced by underscores
-- (e.g. "Tech News" → "tech_news"). Two topics with identical slugs are duplicates.
ALTER TABLE topics ADD COLUMN slug TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_topics_slug ON topics(slug);
