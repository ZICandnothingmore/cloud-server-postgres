ALTER TABLE key_invitations
DROP CONSTRAINT IF EXISTS key_invitations_status_check;

ALTER TABLE key_invitations
ADD CONSTRAINT key_invitations_status_check
CHECK (status IN ('PENDING', 'CLAIMED', 'FAILED', 'REVOKED', 'EXPIRED', 'CANCELLED'));

CREATE TABLE IF NOT EXISTS revoke_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    key_id TEXT NOT NULL,
    module_id TEXT NOT NULL REFERENCES vehicles(module_id) ON DELETE CASCADE,

    requester_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    status VARCHAR(30) NOT NULL CHECK (status IN ('PENDING', 'REVOKED', 'FAILED')),
    reason TEXT,
    key_snapshot JSONB,
    failure_reason TEXT,
    synced_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_revoke_jobs_key_module
ON revoke_jobs(key_id, module_id);

CREATE INDEX IF NOT EXISTS idx_revoke_jobs_module_id
ON revoke_jobs(module_id);

CREATE INDEX IF NOT EXISTS idx_revoke_jobs_requester_id
ON revoke_jobs(requester_id);

CREATE INDEX IF NOT EXISTS idx_revoke_jobs_target_user_id
ON revoke_jobs(target_user_id);

CREATE INDEX IF NOT EXISTS idx_revoke_jobs_status
ON revoke_jobs(status);
