CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    identity_pk TEXT NOT NULL,
    device_name VARCHAR(255),
    fcm_token TEXT,
    last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT unique_user_identity UNIQUE (user_id, identity_pk)
);

CREATE TABLE IF NOT EXISTS vehicles (
    module_id TEXT PRIMARY KEY,
    vin VARCHAR(50) UNIQUE,
    vehicle_identity_pk TEXT NOT NULL,
    current_owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vehicle_name VARCHAR(255),
    status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS digital_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    key_id TEXT NOT NULL,
    module_id TEXT NOT NULL REFERENCES vehicles(module_id) ON DELETE CASCADE,

    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    holder_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    parent_key_id TEXT,

    role VARCHAR(20) NOT NULL CHECK (role IN ('OWNER', 'FRIEND')),
    state VARCHAR(30) NOT NULL CHECK (state IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'PROVISIONING')),

    permissions INTEGER NOT NULL DEFAULT 0,

    friendly_name VARCHAR(255),
    holder_nickname VARCHAR(255),

    device_pk TEXT NOT NULL,
    vehicle_pk TEXT NOT NULL,

    validity_start BIGINT NOT NULL,
    validity_end BIGINT NOT NULL,

    usage_limit INTEGER DEFAULT 0,

    car_metadata JSONB,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT unique_key_per_module UNIQUE (key_id, module_id)
);

CREATE INDEX IF NOT EXISTS idx_digital_keys_module_id
ON digital_keys(module_id);

CREATE INDEX IF NOT EXISTS idx_digital_keys_owner_id
ON digital_keys(owner_id);

CREATE INDEX IF NOT EXISTS idx_digital_keys_holder_id
ON digital_keys(holder_id);

CREATE INDEX IF NOT EXISTS idx_digital_keys_parent_key_id
ON digital_keys(parent_key_id);

CREATE INDEX IF NOT EXISTS idx_digital_keys_state
ON digital_keys(state);

CREATE TABLE IF NOT EXISTS key_invitations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    recipient_email VARCHAR(255) NOT NULL,

    module_id TEXT NOT NULL REFERENCES vehicles(module_id) ON DELETE CASCADE,

    attestation_package TEXT NOT NULL,

    pin_hash TEXT NOT NULL,

    status VARCHAR(30) NOT NULL CHECK (status IN ('PENDING', 'CLAIMED', 'FAILED', 'REVOKED', 'EXPIRED', 'CANCELLED')),

    metadata_snapshot JSONB,

    claim_attempts INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_key_invitations_recipient_email
ON key_invitations(recipient_email);

CREATE INDEX IF NOT EXISTS idx_key_invitations_sender_id
ON key_invitations(sender_id);

CREATE INDEX IF NOT EXISTS idx_key_invitations_module_id
ON key_invitations(module_id);

CREATE INDEX IF NOT EXISTS idx_key_invitations_status
ON key_invitations(status);

-- Chặn trùng lời mời đang pending cho cùng người nhận + cùng module:
CREATE UNIQUE INDEX IF NOT EXISTS unique_pending_invitation
ON key_invitations(recipient_email, module_id)
WHERE status = 'PENDING';

-- sample data for digital keys
DO $$
DECLARE
    v_owner_id UUID;
BEGIN
    SELECT id INTO v_owner_id
    FROM users
    WHERE email = 'owner@gmail.com';

    IF v_owner_id IS NULL THEN
        RAISE EXCEPTION 'Không tìm thấy user owner@gmail.com';
    END IF;

    INSERT INTO vehicles (
        module_id,
        vin,
        vehicle_identity_pk,
        current_owner_id,
        vehicle_name,
        status
    )
    VALUES (
        '00112233445566778899aabbccddeeff',
        'VIN001OWNER',
        'ffeeddccbbaa99887766554433221100',
        v_owner_id,
        'VinFast VF8 của Owner',
        'ACTIVE'
    )
    ON CONFLICT (module_id) DO UPDATE SET
        vin = EXCLUDED.vin,
        vehicle_identity_pk = EXCLUDED.vehicle_identity_pk,
        current_owner_id = EXCLUDED.current_owner_id,
        vehicle_name = EXCLUDED.vehicle_name,
        status = EXCLUDED.status,
        updated_at = CURRENT_TIMESTAMP;

    INSERT INTO digital_keys (
        key_id,
        module_id,
        owner_id,
        holder_id,
        parent_key_id,
        role,
        state,
        permissions,
        friendly_name,
        holder_nickname,
        device_pk,
        vehicle_pk,
        validity_start,
        validity_end,
        usage_limit,
        car_metadata
    )
    VALUES (
        'a1b2c3d4e5f60708',
        '00112233445566778899aabbccddeeff',
        v_owner_id,
        v_owner_id,
        NULL,
        'OWNER',
        'ACTIVE',
        15,
        'VinFast VF8 của Owner',
        'Owner phone',
        'abcdef1234567890',
        'ffeeddccbbaa99887766554433221100',
        1778140000,
        0,
        0,
        '{"brandName":"VinFast","modelName":"VF8","licensePlate":"51A-12345","color":"White"}'
    )
    ON CONFLICT (key_id, module_id) DO UPDATE SET
        owner_id = EXCLUDED.owner_id,
        holder_id = EXCLUDED.holder_id,
        role = EXCLUDED.role,
        state = EXCLUDED.state,
        permissions = EXCLUDED.permissions,
        friendly_name = EXCLUDED.friendly_name,
        holder_nickname = EXCLUDED.holder_nickname,
        device_pk = EXCLUDED.device_pk,
        vehicle_pk = EXCLUDED.vehicle_pk,
        validity_start = EXCLUDED.validity_start,
        validity_end = EXCLUDED.validity_end,
        usage_limit = EXCLUDED.usage_limit,
        car_metadata = EXCLUDED.car_metadata,
        updated_at = CURRENT_TIMESTAMP;
END $$;

-- tạo bảng lưu refresh token vì refresh token sống lâu nên nếu muốn logout, thu hồi phiên đăng nhập, hoặc biết thiết bị nào đang đăng nhập thì cần lưu.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES user_devices(id) ON DELETE CASCADE,

    token_hash TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE key_invitations
ALTER COLUMN pin_hash DROP NOT NULL;

ALTER TABLE key_invitations
ADD COLUMN IF NOT EXISTS parent_key_id TEXT;

CREATE INDEX IF NOT EXISTS idx_key_invitations_parent_key_id
ON key_invitations(parent_key_id);

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
