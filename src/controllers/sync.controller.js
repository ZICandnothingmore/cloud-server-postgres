const pool = require("../config/db");
const { normalizeHex, normalizeHexOptional } = require("../utils/hex");

module.exports = {
    uploadKey: async (req, res) => {
        try {
            const {
                key_id,
                keyId,
    
                module_id,
                moduleID,
                moduleId,
    
                owner_id,
                ownerId,
    
                parent_key_id,
                parentKeyId,
    
                role,
                state,
                keyState,
    
                permissions,
    
                friendly_name,
                friendlyName,
    
                holder_nickname,
                holderNickname,
    
                device_pk,
                devicePublicKey,
    
                vehicle_pk,
                vehiclePublicKey,
    
                validity_start,
                validityStart,
    
                validity_end,
                validityEnd,
    
                usage_limit,
                usageLimit,
    
                car_metadata,
                metadata
            } = req.body;
    
            const finalKeyId = key_id || keyId;
            const finalModuleId = module_id || moduleID || moduleId;
            const finalParentKeyId = parent_key_id || parentKeyId || null;
            const finalState = state || keyState || "ACTIVE";
            const finalFriendlyName = friendly_name || friendlyName || null;
            const finalHolderNickname = holder_nickname || holderNickname || null;
            const finalDevicePk = device_pk || devicePublicKey;
            const finalVehiclePk = vehicle_pk || vehiclePublicKey;
            const finalValidityStart = validity_start ?? validityStart ?? 0;
            const finalValidityEnd = validity_end ?? validityEnd ?? 0;
            const finalUsageLimit = usage_limit ?? usageLimit ?? 0;
            const finalMetadata = car_metadata || metadata || null;
    
            if (!finalKeyId || !finalModuleId || !role || !finalState || !finalDevicePk || !finalVehiclePk) {
                return res.status(400).json({
                    error: "keyId, moduleID, role, keyState/state, devicePublicKey, vehiclePublicKey là bắt buộc"
                });
            }
    
            let normalizedKeyId;
            let normalizedModuleId;
            let normalizedParentKeyId = null;
            let normalizedDevicePk;
            let normalizedVehiclePk;
    
            try {
                normalizedKeyId = normalizeHex(finalKeyId, "keyId");
                normalizedModuleId = normalizeHex(finalModuleId, "moduleID");
                normalizedDevicePk = normalizeHex(finalDevicePk, "devicePublicKey");
                normalizedVehiclePk = normalizeHex(finalVehiclePk, "vehiclePublicKey");
    
                if (finalParentKeyId) {
                    normalizedParentKeyId = normalizeHexOptional(finalParentKeyId);
                }
            } catch (err) {
                return res.status(400).json({
                    error: err.message
                });
            }
    
            const normalizedRole = String(role).trim().toUpperCase();
    
            let normalizedState = String(finalState).trim().toUpperCase();
    
            // App đôi khi gửi keyState = CLAIMED, nhưng CLAIMED là status của invitation,
            // không phải state của digital key.
            if (normalizedState === "CLAIMED") {
                normalizedState = "ACTIVE";
            }
    
            if (!["OWNER", "FRIEND"].includes(normalizedRole)) {
                return res.status(400).json({
                    error: "role chỉ được là OWNER hoặc FRIEND"
                });
            }
    
            if (!["ACTIVE", "SUSPENDED", "REVOKED", "PROVISIONING"].includes(normalizedState)) {
                return res.status(400).json({
                    error: "state/keyState chỉ được là ACTIVE, SUSPENDED, REVOKED hoặc PROVISIONING"
                });
            }
    
            let finalOwnerId = owner_id || ownerId || null;
    
            if (normalizedRole === "OWNER") {
                finalOwnerId = req.auth.userId;
    
                // Quan trọng:
                // Owner upload key thì server tự đảm bảo vehicles có module này.
                // Như vậy app không bị fail nếu chưa gọi /vehicle/register.
                await pool.query(
                    `
                    INSERT INTO vehicles (
                        module_id,
                        vin,
                        vehicle_identity_pk,
                        current_owner_id,
                        vehicle_name,
                        status
                    )
                    VALUES ($1, $2, $3, $4::uuid, $5, 'ACTIVE')
                    ON CONFLICT (module_id)
                    DO UPDATE SET
                        vehicle_identity_pk = EXCLUDED.vehicle_identity_pk,
                        current_owner_id = EXCLUDED.current_owner_id,
                        vehicle_name = COALESCE(EXCLUDED.vehicle_name, vehicles.vehicle_name),
                        status = 'ACTIVE',
                        updated_at = CURRENT_TIMESTAMP
                    `,
                    [
                        normalizedModuleId,
                        finalMetadata?.vin || finalMetadata?.VIN || null,
                        normalizedVehiclePk,
                        req.auth.userId,
                        finalFriendlyName || finalMetadata?.modelName || "Digital Key Vehicle"
                    ]
                );
            }
    
            if (normalizedRole === "FRIEND") {
                // Friend key phải thuộc một owner key gốc.
                // Nếu app có parentKeyId thì tìm bằng parentKeyId.
                // Nếu không có, tìm OWNER key ACTIVE theo moduleID.
                let parentResult;
    
                if (normalizedParentKeyId) {
                    parentResult = await pool.query(
                        `
                        SELECT owner_id, key_id, vehicle_pk, car_metadata, friendly_name
                        FROM digital_keys
                        WHERE key_id = $1
                          AND module_id = $2
                          AND role = 'OWNER'
                          AND state = 'ACTIVE'
                        `,
                        [normalizedParentKeyId, normalizedModuleId]
                    );
                } else {
                    parentResult = await pool.query(
                        `
                        SELECT owner_id, key_id, vehicle_pk, car_metadata, friendly_name
                        FROM digital_keys
                        WHERE module_id = $1
                          AND role = 'OWNER'
                          AND state = 'ACTIVE'
                        ORDER BY created_at DESC
                        LIMIT 1
                        `,
                        [normalizedModuleId]
                    );
                }
    
                if (parentResult.rows.length === 0) {
                    return res.status(404).json({
                        error: "Không tìm thấy OWNER key gốc cho FRIEND key"
                    });
                }
    
                const ownerKey = parentResult.rows[0];
    
                finalOwnerId = ownerKey.owner_id;
                normalizedParentKeyId = normalizedParentKeyId || ownerKey.key_id;
            }
            
            if (!finalOwnerId) {
                return res.status(400).json({
                    error: "Không xác định được owner_id cho digital key",
                    debug: {
                        role: normalizedRole,
                        tokenUserId: req.auth.userId,
                        tokenEmail: req.auth.email
                    }
                });
            }
    
            const result = await pool.query(
                `
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
                    $1, $2,
                    $3::uuid,
                    $4::uuid,
                    $5, $6, $7, $8, $9, $10,
                    $11, $12, $13, $14, $15, $16
                )
                ON CONFLICT (key_id, module_id)
                DO UPDATE SET
                    owner_id = EXCLUDED.owner_id,
                    holder_id = EXCLUDED.holder_id,
                    parent_key_id = EXCLUDED.parent_key_id,
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
                    updated_at = CURRENT_TIMESTAMP
                RETURNING *
                `,
                [
                        normalizedKeyId,
                        normalizedModuleId,
                        finalOwnerId,
                        req.auth.userId,
                        normalizedParentKeyId,
                        normalizedRole,
                        normalizedState,
                        permissions ?? 0,
                        finalFriendlyName,
                        finalHolderNickname,
                        normalizedDevicePk,
                        normalizedVehiclePk,
                        Number(finalValidityStart),
                        Number(finalValidityEnd),
                        Number(finalUsageLimit),
                        finalMetadata
                ]
            );
    
            return res.json({
                message: "Sync key thành công",
                key: result.rows[0]
            });
        } catch (err) {
            return res.status(500).json({
                error: err.message
            });
        }
    },

    listKeys: async (req, res) => {
        try {
            const result = await pool.query(
                `
                SELECT
                    dk.id,
                    dk.key_id,
                    dk.module_id,

                    owner.email AS owner_email,
                    holder.email AS holder_email,

                    dk.owner_id,
                    dk.holder_id,
                    dk.parent_key_id,

                    dk.role,
                    dk.state,
                    dk.permissions,

                    dk.friendly_name,
                    dk.holder_nickname,

                    dk.device_pk,
                    dk.vehicle_pk,

                    dk.validity_start,
                    dk.validity_end,
                    dk.usage_limit,

                    dk.car_metadata,

                    dk.created_at,
                    dk.updated_at
                FROM digital_keys dk
                JOIN users owner ON owner.id = dk.owner_id
                JOIN users holder ON holder.id = dk.holder_id
                WHERE dk.holder_id = $1
                  AND dk.state IN ('ACTIVE', 'PROVISIONING')
                ORDER BY dk.created_at DESC
                `,
                [req.auth.userId]
            );

            const keys = result.rows.map(row => ({
                id: row.id,

                keyId: row.key_id,
                moduleID: row.module_id,

                ownerEmail: row.owner_email,
                holderEmail: row.holder_email,

                ownerId: row.owner_id,
                holderId: row.holder_id,

                parentKeyId: row.parent_key_id,

                role: row.role,
                keyState: row.state,

                permissions: row.permissions,

                friendlyName: row.friendly_name,
                holderNickname: row.holder_nickname,

                devicePublicKey: row.device_pk,
                vehiclePublicKey: row.vehicle_pk,

                validityStart: Number(row.validity_start),
                validityEnd: Number(row.validity_end),
                usageLimit: row.usage_limit,

                metadata: row.car_metadata || {},

                createdAt: row.created_at,
                updatedAt: row.updated_at
            }));

            return res.json(keys);
        } catch (err) {
            return res.status(500).json({
                error: err.message
            });
        }
    }
};