-- Add invite_id to users, linking each user to the invite they signed up with.
ALTER TABLE users ADD COLUMN invite_id TEXT REFERENCES invites(id);
CREATE INDEX IF NOT EXISTS idx_users_invite_id ON users(invite_id);
