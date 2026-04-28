-- Add link_url to threads for link-style posts.
--
-- A thread with a non-NULL link_url is a "link post": the root post body
-- represents the user's framing/context (which may be empty for v1), and
-- link_url is the canonical URL the post is about. NULL means a regular
-- text post.
--
-- The URL is stored unsigned (parallel to title) and is immutable once set.

ALTER TABLE threads ADD COLUMN link_url TEXT;