-- Add a slug column for URL routing and uniqueness enforcement.
-- The slug is the lowercased name with spaces and hyphens replaced by underscores
-- (e.g. "Tech News" → "tech_news"). Two areas with identical slugs are duplicates.
ALTER TABLE areas ADD COLUMN slug TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_areas_slug ON areas(slug);
