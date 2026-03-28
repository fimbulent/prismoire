-- Store the user UUID generated during signup_begin so that signup_complete
-- uses the same ID that was embedded in the passkey credential. This ensures
-- discoverable authentication can look up the user by the credential's userHandle.
ALTER TABLE auth_challenges ADD COLUMN user_id TEXT;
