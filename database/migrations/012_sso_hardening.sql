ALTER TABLE auth_sessions ADD COLUMN session_token_hash TEXT;
ALTER TABLE auth_sessions ADD COLUMN last_seen_at INTEGER;
ALTER TABLE auth_sessions ADD COLUMN updated_at INTEGER;

ALTER TABLE auth_otp_challenges ADD COLUMN code_hash TEXT;
ALTER TABLE auth_otp_challenges ADD COLUMN used_at INTEGER;
ALTER TABLE auth_otp_challenges ADD COLUMN updated_at INTEGER;
ALTER TABLE auth_otp_challenges ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_auth_sessions_token_hash
ON auth_sessions(session_token_hash);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_status_expires
ON auth_sessions(status, expires_at);

CREATE INDEX IF NOT EXISTS idx_auth_otp_code_hash
ON auth_otp_challenges(code_hash);

CREATE INDEX IF NOT EXISTS idx_auth_otp_identity_status
ON auth_otp_challenges(identity_type, identity_value, status);

UPDATE auth_sessions
SET updated_at = COALESCE(updated_at, created_at),
    last_seen_at = COALESCE(last_seen_at, created_at)
WHERE updated_at IS NULL OR last_seen_at IS NULL;

UPDATE auth_otp_challenges
SET updated_at = COALESCE(updated_at, created_at)
WHERE updated_at IS NULL;
