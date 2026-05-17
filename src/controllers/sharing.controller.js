const pool = require("../config/db");
const { normalizeBinaryToHex } = require("../utils/binary");

function isEmptyMetadata(metadata) {
    if (!metadata) return true;

    return !metadata.brandName &&
        !metadata.modelName &&
        !metadata.licensePlate &&
        !metadata.color &&
        !metadata.imageUrl &&
        !metadata.brand_name &&
        !metadata.model_name &&
        !metadata.license_plate &&
        !metadata.image_url;
}

module.exports = {
    checkLegality: async (req, res) => {
        try {
            const recipientEmail = req.body.recipientEmail || req.body.recipient_email;
    
            const rawParentKeyId =
                req.body.parentKeyId ||
                req.body.parent_key_id ||
                req.body.parentKeyID;
    
            if (!recipientEmail || !rawParentKeyId) {
                return res.status(400).json({
                    isLegal: false,
                    message: "recipientEmail và parentKeyId là bắt buộc"
                });
            }
    
            const normalizedRecipientEmail = recipientEmail.trim().toLowerCase();
            const parentKeyIdHex = normalizeBinaryToHex(rawParentKeyId, "parentKeyId");
    
            const senderEmail = req.auth.email;
            const senderUserId = req.auth.userId;
    
            if (senderEmail === normalizedRecipientEmail) {
                return res.status(400).json({
                    isLegal: false,
                    message: "Cannot share with yourself"
                });
            }
    
            const recipientResult = await pool.query(
                `
                SELECT id, email, display_name
                FROM users
                WHERE email = $1
                `,
                [normalizedRecipientEmail]
            );
    
            if (recipientResult.rows.length === 0) {
                return res.status(404).json({
                    isLegal: false,
                    message: "Recipient email chưa tồn tại trong hệ thống"
                });
            }
    
            const ownerKeyResult = await pool.query(
                `
                SELECT key_id, module_id, owner_id, holder_id, role, state
                FROM digital_keys
                WHERE key_id = $1
                  AND owner_id = $2
                  AND holder_id = $2
                  AND role = 'OWNER'
                  AND state = 'ACTIVE'
                `,
                [parentKeyIdHex, senderUserId]
            );
    
            if (ownerKeyResult.rows.length === 0) {
                return res.status(403).json({
                    isLegal: false,
                    message: "Bạn không sở hữu parentKeyId hợp lệ để chia sẻ"
                });
            }
    
            const ownerKey = ownerKeyResult.rows[0];
    
            const pendingResult = await pool.query(
                `
                SELECT id
                FROM key_invitations
                WHERE recipient_email = $1
                  AND module_id = $2
                  AND status = 'PENDING'
                `,
                [normalizedRecipientEmail, ownerKey.module_id]
            );
    
            if (pendingResult.rows.length > 0) {
                return res.status(409).json({
                    isLegal: false,
                    message: "Đã tồn tại lời mời PENDING cho người nhận và xe này"
                });
            }
    
            return res.json({
                isLegal: true,
                message: "Có thể chia sẻ key",
                parentKeyId: parentKeyIdHex,
                moduleID: ownerKey.module_id,
                recipient: recipientResult.rows[0]
            });
        } catch (err) {
            return res.status(500).json({
                isLegal: false,
                message: err.message
            });
        }
    },

    invite: async (req, res) => {
        try {
            const recipientEmail = req.body.recipientEmail || req.body.recipient_email;
    
            const rawModuleId =
                req.body.moduleID ||
                req.body.moduleId ||
                req.body.module_id;
    
            const rawParentKeyId =
                req.body.parentKeyId ||
                req.body.parent_key_id ||
                req.body.parentKeyID ||
                null;
    
            const rawAp =
                req.body.ap_blob ||
                req.body.apBlob ||
                req.body.ap ||
                req.body.attestation_package ||
                req.body.attestationPackage;
    
            const metadataSnapshot =
                req.body.car_metadata ||
                req.body.carMetadata ||
                req.body.metadata_snapshot ||
                req.body.metadataSnapshot ||
                null;
    
            const pinHash =
                req.body.pin_hash ||
                req.body.pinHash ||
                null;
    
            if (!recipientEmail || !rawModuleId || !rawAp) {
                return res.status(400).json({
                    error: "recipientEmail, moduleID và ap_blob là bắt buộc"
                });
            }
    
            const normalizedRecipientEmail = recipientEmail.trim().toLowerCase();
            const moduleIdHex = normalizeBinaryToHex(rawModuleId, "moduleID");
            const apHex = normalizeBinaryToHex(rawAp, "ap_blob");
            const parentKeyIdHex = rawParentKeyId
                ? normalizeBinaryToHex(rawParentKeyId, "parentKeyId")
                : null;
    
            if (req.auth.email === normalizedRecipientEmail) {
                return res.status(400).json({
                    error: "Cannot share with yourself"
                });
            }
    
            const recipientResult = await pool.query(
                `
                SELECT id, email, display_name
                FROM users
                WHERE email = $1
                `,
                [normalizedRecipientEmail]
            );
    
            if (recipientResult.rows.length === 0) {
                return res.status(404).json({
                    error: "Người nhận chưa đăng ký tài khoản"
                });
            }
    
            const ownerKeyResult = await pool.query(
                `
                SELECT *
                FROM digital_keys
                WHERE module_id = $1
                  AND owner_id = $2
                  AND holder_id = $2
                  AND role = 'OWNER'
                  AND state = 'ACTIVE'
                `,
                [moduleIdHex, req.auth.userId]
            );
    
            if (ownerKeyResult.rows.length === 0) {
                return res.status(403).json({
                    error: "Bạn không phải Owner hợp lệ của module này"
                });
            }
    
            const invitationResult = await pool.query(
                `
                INSERT INTO key_invitations (
                    sender_id,
                    recipient_email,
                    module_id,
                    parent_key_id,
                    attestation_package,
                    pin_hash,
                    status,
                    metadata_snapshot
                )
                VALUES ($1, $2, $3, $4, $5, $6, 'PENDING', $7)
                RETURNING *
                `,
                [
                    req.auth.userId,
                    normalizedRecipientEmail,
                    moduleIdHex,
                    parentKeyIdHex,
                    apHex,
                    pinHash,
                    metadataSnapshot
                ]
            );
    
            const fcmResult = await pool.query(
                `
                SELECT fcm_token
                FROM user_devices
                WHERE user_id = $1
                  AND fcm_token IS NOT NULL
                ORDER BY last_active DESC
                `,
                [recipientResult.rows[0].id]
            );
    
            const fcmTokens = fcmResult.rows.map(row => row.fcm_token);
    
            return res.status(200).json({
                message: "Upload invitation thành công",
                invitation: invitationResult.rows[0],
                push: {
                    enabled: false,
                    mode: "MOCK",
                    wouldSendToTokens: fcmTokens,
                    note: fcmTokens.length > 0
                        ? "Đã tìm thấy FCM token của Friend, sau này có thể gửi push thật"
                        : "Friend chưa có FCM token"
                }
            });
        } catch (err) {
            if (err.code === "23505") {
                return res.status(409).json({
                    error: "Đã tồn tại lời mời PENDING cho người nhận và xe này"
                });
            }
    
            return res.status(500).json({
                error: err.message
            });
        }
    },

    pending: async (req, res) => {
        try {
            const result = await pool.query(
                `
                SELECT
                    ki.id,
                    ki.sender_id,
                    sender.email AS sender_email,
                    sender.display_name AS sender_name,
                    ki.recipient_email,
                    ki.module_id,
                    ki.parent_key_id,
                    ki.attestation_package,
                    ki.status,
                    ki.metadata_snapshot,
                    ki.claim_attempts,
                    ki.created_at,
                    ki.updated_at
                FROM key_invitations ki
                JOIN users sender ON sender.id = ki.sender_id
                WHERE ki.recipient_email = $1
                  AND ki.status = 'PENDING'
                ORDER BY ki.created_at DESC
                `,
                [req.auth.email]
            );
    
            const invitations = result.rows.map(row => ({
                id: row.id,
    
                sender_id: row.sender_id,
                sender_email: row.sender_email,
                sender_name: row.sender_name,
    
                senderId: row.sender_id,
                senderEmail: row.sender_email,
                senderName: row.sender_name,
    
                recipient_email: row.recipient_email,
                recipientEmail: row.recipient_email,
    
                module_id: row.module_id,
                moduleID: row.module_id,
    
                parent_key_id: row.parent_key_id,
                parentKeyId: row.parent_key_id,
    
                status: row.status,
    
                metadata_snapshot: row.metadata_snapshot,
                car_metadata: row.metadata_snapshot,
                metadata: row.metadata_snapshot,
    
                attestation_package: row.attestation_package,
                ap_blob: row.attestation_package,
                apBlob: row.attestation_package,
                ap: row.attestation_package,
                attestationPackage: row.attestation_package,
    
                claim_attempts: row.claim_attempts,
                claimAttempts: row.claim_attempts,
    
                created_at: row.created_at,
                updated_at: row.updated_at
            }));
    
            return res.json(invitations);
        } catch (err) {
            return res.status(500).json({
                error: err.message
            });
        }
    },

    claim: async (req, res) => {
        try {
            const invitationId =
                req.body.invitation_id ||
                req.body.invitationId ||
                req.body.id;
    
            if (!invitationId) {
                return res.status(400).json({
                    error: "invitation_id là bắt buộc"
                });
            }
    
            const invitationResult = await pool.query(
                `
                SELECT *
                FROM key_invitations
                WHERE id = $1
                  AND recipient_email = $2
                `,
                [invitationId, req.auth.email]
            );
    
            if (invitationResult.rows.length === 0) {
                return res.status(404).json({
                    error: "Không tìm thấy lời mời thuộc tài khoản hiện tại"
                });
            }
    
            const invitation = invitationResult.rows[0];
    
            if (invitation.status !== "PENDING") {
                return res.status(400).json({
                    error: `Lời mời không còn ở trạng thái PENDING. Trạng thái hiện tại: ${invitation.status}`
                });
            }
    
            return res.json({
                message: "Tải lời mời thành công",
                invitation_id: invitation.id,
                moduleID: invitation.module_id,
                parentKeyId: invitation.parent_key_id,
                ap_blob: invitation.attestation_package,
                car_metadata: invitation.metadata_snapshot,
                status: invitation.status
            });
        } catch (err) {
            return res.status(500).json({
                error: err.message
            });
        }
    },

    report: async (req, res) => {
        const client = await pool.connect();
    
        try {
            await client.query("BEGIN");
    
            const invitationId =
                req.body.invitation_id ||
                req.body.invitationId ||
                req.body.id;
    
            const status =
                req.body.status ||
                req.body.outcome;
    
            if (!invitationId || !status) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    error: "invitation_id và status là bắt buộc"
                });
            }
    
            const normalizedStatus = String(status).trim().toUpperCase();
    
            if (!["CLAIMED", "FAILED"].includes(normalizedStatus)) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    error: "status chỉ được là CLAIMED hoặc FAILED"
                });
            }
    
            const invitationResult = await client.query(
                `
                SELECT *
                FROM key_invitations
                WHERE id = $1
                  AND recipient_email = $2
                  AND status = 'PENDING'
                `,
                [invitationId, req.auth.email]
            );
    
            if (invitationResult.rows.length === 0) {
                await client.query("ROLLBACK");
                return res.status(404).json({
                    error: "Không tìm thấy lời mời PENDING thuộc tài khoản hiện tại"
                });
            }
    
            const invitation = invitationResult.rows[0];
    
            let createdFriendKey = null;
    
            if (normalizedStatus === "CLAIMED") {
                const keyId =
                    req.body.keyId ||
                    req.body.key_id;
    
                const devicePublicKey =
                    req.body.devicePublicKey ||
                    req.body.device_pk ||
                    req.body.devicePk;
    
                let vehiclePublicKey =
                    req.body.vehiclePublicKey ||
                    req.body.vehicle_pk ||
                    req.body.vehiclePk ||
                    null;
    
                const permissions =
                    req.body.permissions ?? 0;
    
                const holderNickname =
                    req.body.holderNickname ||
                    req.body.holder_nickname ||
                    req.auth.email;
    
                const validityStart =
                    req.body.validityStart ??
                    req.body.validity_start ??
                    0;
    
                const validityEnd =
                    req.body.validityEnd ??
                    req.body.validity_end ??
                    0;
    
                const usageLimit =
                    req.body.usageLimit ??
                    req.body.usage_limit ??
                    0;
    
                let keyState =
                    req.body.keyState ||
                    req.body.state ||
                    "ACTIVE";
    
                keyState = String(keyState).trim().toUpperCase();
    
                // CLAIMED là status của invitation, không phải state của digital key
                if (keyState === "CLAIMED") {
                    keyState = "ACTIVE";
                }
    
                if (!["ACTIVE", "SUSPENDED", "REVOKED", "PROVISIONING"].includes(keyState)) {
                    keyState = "ACTIVE";
                }
    
                if (!keyId || !devicePublicKey) {
                    await client.query("ROLLBACK");
                    return res.status(400).json({
                        error: "CLAIMED cần keyId và devicePublicKey để lưu FRIEND key"
                    });
                }
    
                const normalizedKeyId = String(keyId).trim().toLowerCase();
                const normalizedModuleId = String(invitation.module_id).trim().toLowerCase();
    
                let normalizedParentKeyId = invitation.parent_key_id
                    ? String(invitation.parent_key_id).trim().toLowerCase()
                    : null;
    
                let ownerKeyResult;
    
                if (normalizedParentKeyId) {
                    ownerKeyResult = await client.query(
                        `
                        SELECT key_id, module_id, owner_id, vehicle_pk, car_metadata, friendly_name
                        FROM digital_keys
                        WHERE key_id = $1
                          AND module_id = $2
                          AND owner_id = $3::uuid
                          AND role = 'OWNER'
                          AND state = 'ACTIVE'
                        LIMIT 1
                        `,
                        [normalizedParentKeyId, normalizedModuleId, invitation.sender_id]
                    );
                } else {
                    ownerKeyResult = await client.query(
                        `
                        SELECT key_id, module_id, owner_id, vehicle_pk, car_metadata, friendly_name
                        FROM digital_keys
                        WHERE module_id = $1
                          AND owner_id = $2::uuid
                          AND role = 'OWNER'
                          AND state = 'ACTIVE'
                        ORDER BY created_at DESC
                        LIMIT 1
                        `,
                        [normalizedModuleId, invitation.sender_id]
                    );
                }
    
                if (ownerKeyResult.rows.length === 0) {
                    await client.query("ROLLBACK");
                    return res.status(404).json({
                        error: "Không tìm thấy OWNER key gốc để tạo FRIEND key",
                        debug: {
                            moduleID: normalizedModuleId,
                            senderId: invitation.sender_id,
                            parentKeyId: normalizedParentKeyId
                        }
                    });
                }
    
                const ownerKey = ownerKeyResult.rows[0];
    
                normalizedParentKeyId = normalizedParentKeyId || ownerKey.key_id;
    
                // Nếu app gửi vehiclePublicKey rỗng thì lấy từ OWNER key
                if (!vehiclePublicKey || String(vehiclePublicKey).trim() === "") {
                    vehiclePublicKey = ownerKey.vehicle_pk;
                }
    
                if (!vehiclePublicKey || String(vehiclePublicKey).trim() === "") {
                    await client.query("ROLLBACK");
                    return res.status(400).json({
                        error: "Không có vehiclePublicKey. App không gửi và OWNER key cũng không có vehicle_pk."
                    });
                }
    
                const normalizedDevicePk = String(devicePublicKey).trim().toLowerCase();
                const normalizedVehiclePk = String(vehiclePublicKey).trim().toLowerCase();
    
                const requestMetadata =
                    req.body.metadata ||
                    req.body.car_metadata ||
                    null;
    
                const metadata = isEmptyMetadata(requestMetadata)
                    ? (invitation.metadata_snapshot || ownerKey.car_metadata || null)
                    : requestMetadata;
    
                const friendlyName =
                    req.body.friendlyName ||
                    req.body.friendly_name ||
                    ownerKey.friendly_name ||
                    metadata?.modelName ||
                    metadata?.model_name ||
                    "Shared Digital Key";
    
                const friendKeyResult = await client.query(
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
                        $5,
                        'FRIEND',
                        $6, $7, $8, $9,
                        $10, $11, $12, $13, $14, $15
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
                        invitation.sender_id,
                        req.auth.userId,
                        normalizedParentKeyId,
                        keyState,
                        Number(permissions),
                        friendlyName,
                        holderNickname,
                        normalizedDevicePk,
                        normalizedVehiclePk,
                        Number(validityStart),
                        Number(validityEnd),
                        Number(usageLimit),
                        metadata
                    ]
                );
    
                createdFriendKey = friendKeyResult.rows[0];
            }
    
            const updatedInvitationResult = await client.query(
                `
                UPDATE key_invitations
                SET status = $1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $2
                RETURNING *
                `,
                [normalizedStatus, invitationId]
            );
    
            await client.query("COMMIT");
    
            return res.json({
                message: "Cập nhật kết quả sharing thành công",
                invitation: updatedInvitationResult.rows[0],
                friendKey: createdFriendKey
            });
        } catch (err) {
            await client.query("ROLLBACK");
    
            console.error("SHARING REPORT ERROR:", {
                message: err.message,
                detail: err.detail,
                hint: err.hint,
                position: err.position,
                stack: err.stack
            });
    
            return res.status(500).json({
                error: err.message,
                detail: err.detail,
                hint: err.hint
            });
        } finally {
            client.release();
        }
    }
}