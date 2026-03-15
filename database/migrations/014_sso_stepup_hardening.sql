ALTER TABLE auth_step_up_challenges ADD COLUMN code_hash TEXT;
ALTER TABLE auth_step_up_challenges ADD COLUMN used_at INTEGER;
ALTER TABLE auth_step_up_challenges ADD COLUMN updated_at INTEGER;
ALTER TABLE auth_step_up_challenges ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_auth_step_up_user_reason_status
ON auth_step_up_challenges(user_id, reason, status);

CREATE INDEX IF NOT EXISTS idx_auth_step_up_code_hash
ON auth_step_up_challenges(code_hash);

UPDATE auth_step_up_challenges
SET updated_at = COALESCE(updated_at, created_at)
WHERE updated_at IS NULL;
