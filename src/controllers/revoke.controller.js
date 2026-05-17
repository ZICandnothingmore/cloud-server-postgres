const pool = require("../config/db");
const bcrypt = require("bcrypt");

function normalizeHex(value) {
    if (!value) return null;
    return String(value).trim().toLowerCase();
}

function normalizeEmail(value) {
    if (!value) return null;
    return String(value).trim().toLowerCase();
}

module.exports = {
    // =========================================================
    // 1. Owner gửi yêu cầu revoke Friend key
    // Chỉ tạo revoke_jobs.status = PENDING
    // KHÔNG xóa digital_keys ở bước này
    // =========================================================
    createFriendRevokeRequest: async (req, res) => {
        const client = await pool.connect();

        try {
            await client.query("BEGIN");

            const rawModuleId =
                req.body.moduleID ||
                req.body.moduleId ||
                req.body.module_id;

            const rawKeyId =
                req.body.keyId ||
                req.body.key_id ||
                null;

            const friendEmail =
                req.body.friendEmail ||
                req.body.friend_email ||
                req.body.holderEmail ||
                req.body.holder_email ||
                null;

            const reason =
                req.body.reason ||
                "Owner gửi yêu cầu thu hồi Friend key";

            if (!rawModuleId) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    error: "moduleID là bắt buộc"
                });
            }

            if (!rawKeyId && !friendEmail) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    error: "Cần truyền keyId hoặc friendEmail để xác định Friend key cần revoke"
                });
            }

            const moduleId = normalizeHex(rawModuleId);
            const keyId = normalizeHex(rawKeyId);
            const normalizedFriendEmail = normalizeEmail(friendEmail);

            // 1. Kiểm tra người gọi có OWNER key ACTIVE trên module này không
            const ownerKeyResult = await client.query(
                `
                SELECT *
                FROM digital_keys
                WHERE module_id = $1
                  AND owner_id = $2::uuid
                  AND holder_id = $2::uuid
                  AND role = 'OWNER'
                  AND state = 'ACTIVE'
                LIMIT 1
                `,
                [moduleId, req.auth.userId]
            );

            if (ownerKeyResult.rows.length === 0) {
                await client.query("ROLLBACK");
                return res.status(403).json({
                    error: "Bạn không có OWNER key ACTIVE trên module này nên không thể gửi yêu cầu revoke"
                });
            }

            // 2. Tìm Friend key cần revoke
            let friendKeyResult;

            if (keyId) {
                friendKeyResult = await client.query(
                    `
                    SELECT
                        dk.*,
                        holder.email AS holder_email
                    FROM digital_keys dk
                    JOIN users holder ON holder.id = dk.holder_id
                    WHERE dk.key_id = $1
                      AND dk.module_id = $2
                      AND dk.owner_id = $3::uuid
                      AND dk.role = 'FRIEND'
                      AND dk.state IN ('ACTIVE', 'PROVISIONING', 'SUSPENDED')
                    LIMIT 1
                    `,
                    [keyId, moduleId, req.auth.userId]
                );
            } else {
                friendKeyResult = await client.query(
                    `
                    SELECT
                        dk.*,
                        holder.email AS holder_email
                    FROM digital_keys dk
                    JOIN users holder ON holder.id = dk.holder_id
                    WHERE dk.module_id = $1
                      AND dk.owner_id = $2::uuid
                      AND holder.email = $3
                      AND dk.role = 'FRIEND'
                      AND dk.state IN ('ACTIVE', 'PROVISIONING', 'SUSPENDED')
                    LIMIT 1
                    `,
                    [moduleId, req.auth.userId, normalizedFriendEmail]
                );
            }

            if (friendKeyResult.rows.length === 0) {
                await client.query("ROLLBACK");
                return res.status(404).json({
                    error: "Không tìm thấy Friend key đang hoạt động để gửi yêu cầu revoke"
                });
            }

            const friendKey = friendKeyResult.rows[0];

            // 3. Chống tạo trùng revoke request PENDING cho cùng key
            const existingJobResult = await client.query(
                `
                SELECT *
                FROM revoke_jobs
                WHERE key_id = $1
                  AND module_id = $2
                  AND requester_id = $3::uuid
                  AND target_user_id = $4::uuid
                  AND status = 'PENDING'
                LIMIT 1
                `,
                [
                    friendKey.key_id,
                    friendKey.module_id,
                    req.auth.userId,
                    friendKey.holder_id
                ]
            );

            if (existingJobResult.rows.length > 0) {
                await client.query("ROLLBACK");
                return res.status(409).json({
                    error: "Đã tồn tại yêu cầu revoke PENDING cho Friend key này",
                    revokeJob: existingJobResult.rows[0]
                });
            }

            // 4. Tạo revoke job PENDING
            // Lưu snapshot key để sau này dù xóa digital_keys vẫn còn lịch sử
            const revokeJobResult = await client.query(
                `
                INSERT INTO revoke_jobs (
                    key_id,
                    module_id,
                    requester_id,
                    target_user_id,
                    status,
                    reason,
                    key_snapshot,
                    created_at,
                    updated_at
                )
                VALUES (
                    $1, $2, $3::uuid, $4::uuid,
                    'PENDING',
                    $5,
                    $6,
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP
                )
                RETURNING *
                `,
                [
                    friendKey.key_id,
                    friendKey.module_id,
                    req.auth.userId,
                    friendKey.holder_id,
                    reason,
                    friendKey
                ]
            );

            await client.query("COMMIT");

            return res.status(201).json({
                message: "Đã gửi yêu cầu revoke Friend key",
                note: "Friend key chưa bị xóa khỏi digital_keys. Key sẽ bị xóa khi Friend xác nhận revoke.",
                revokeJob: revokeJobResult.rows[0],
                friendKey: {
                    keyId: friendKey.key_id,
                    moduleID: friendKey.module_id,
                    holderEmail: friendKey.holder_email,
                    role: friendKey.role,
                    state: friendKey.state
                }
            });
        } catch (err) {
            await client.query("ROLLBACK");

            return res.status(500).json({
                error: err.message,
                detail: err.detail,
                hint: err.hint
            });
        } finally {
            client.release();
        }
    },

    // =========================================================
    // 2. Friend xem các revoke job đang chờ xử lý
    // =========================================================
    listMyRevokeJobs: async (req, res) => {
        try {
            const result = await pool.query(
                `
                SELECT
                    rj.id,
                    rj.key_id,
                    rj.module_id,
                    requester.email AS requester_email,
                    requester.display_name AS requester_name,
                    target.email AS target_email,
                    rj.status,
                    rj.reason,
                    rj.key_snapshot,
                    rj.created_at,
                    rj.updated_at
                FROM revoke_jobs rj
                JOIN users requester ON requester.id = rj.requester_id
                JOIN users target ON target.id = rj.target_user_id
                WHERE rj.target_user_id = $1::uuid
                  AND rj.status = 'PENDING'
                ORDER BY rj.created_at DESC
                `,
                [req.auth.userId]
            );

            return res.json(result.rows);
        } catch (err) {
            return res.status(500).json({
                error: err.message,
                detail: err.detail,
                hint: err.hint
            });
        }
    },

    // =========================================================
    // 3. Friend xác nhận revoke
    // Nếu status = REVOKED/DONE/ACCEPTED:
    // - DELETE Friend key khỏi digital_keys
    // - UPDATE revoke_jobs.status = REVOKED
    // Nếu status = FAILED:
    // - Không xóa key
    // - UPDATE revoke_jobs.status = FAILED
    // =========================================================
    reportRevokeJob: async (req, res) => {
        const client = await pool.connect();

        try {
            await client.query("BEGIN");

            const jobId =
                req.body.jobId ||
                req.body.job_id ||
                req.body.id;

            const status =
                req.body.status ||
                "REVOKED";

            if (!jobId) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    error: "jobId là bắt buộc"
                });
            }

            let normalizedStatus = String(status).trim().toUpperCase();

            if (normalizedStatus === "DONE" || normalizedStatus === "ACCEPTED") {
                normalizedStatus = "REVOKED";
            }

            if (!["REVOKED", "FAILED"].includes(normalizedStatus)) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    error: "status chỉ được là REVOKED, DONE, ACCEPTED hoặc FAILED"
                });
            }

            // 1. Lấy revoke job thuộc Friend hiện tại
            const jobResult = await client.query(
                `
                SELECT *
                FROM revoke_jobs
                WHERE id = $1
                  AND target_user_id = $2::uuid
                  AND status = 'PENDING'
                LIMIT 1
                `,
                [jobId, req.auth.userId]
            );

            if (jobResult.rows.length === 0) {
                await client.query("ROLLBACK");
                return res.status(404).json({
                    error: "Không tìm thấy revoke job PENDING thuộc tài khoản hiện tại"
                });
            }

            const job = jobResult.rows[0];

            let deletedKey = null;

            if (normalizedStatus === "REVOKED") {
                // 2. Friend đã đồng ý/xác nhận xóa local key
                // Server xóa Friend key khỏi digital_keys
                const deletedKeyResult = await client.query(
                    `
                    DELETE FROM digital_keys
                    WHERE key_id = $1
                      AND module_id = $2
                      AND holder_id = $3::uuid
                      AND role = 'FRIEND'
                    RETURNING *
                    `,
                    [
                        job.key_id,
                        job.module_id,
                        req.auth.userId
                    ]
                );

                deletedKey = deletedKeyResult.rows[0] || null;
            }

            // 3. Update trạng thái revoke job
            const updatedJobResult = await client.query(
                `
                UPDATE revoke_jobs
                SET status = $1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $2
                  AND target_user_id = $3::uuid
                RETURNING *
                `,
                [normalizedStatus, jobId, req.auth.userId]
            );

            await client.query("COMMIT");

            return res.json({
                message: normalizedStatus === "REVOKED"
                    ? "Friend đã xác nhận revoke. Server đã xóa Friend key khỏi digital_keys."
                    : "Friend báo revoke thất bại. Server chưa xóa Friend key.",
                revokeJob: updatedJobResult.rows[0],
                deletedKey
            });
        } catch (err) {
            await client.query("ROLLBACK");

            return res.status(500).json({
                error: err.message,
                detail: err.detail,
                hint: err.hint
            });
        } finally {
            client.release();
        }
    },

    // =========================================================
    // 4. Owner tự thu hồi key gốc
    // Trường hợp này không cần Friend đồng ý.
    // Server xóa OWNER key + Friend keys liên quan,
    // lưu lịch sử vào revoke_jobs.
    // =========================================================
    revokeOwnerKey: async (req, res) => {
        const client = await pool.connect();
    
        try {
            await client.query("BEGIN");
    
            const rawModuleId =
                req.body.moduleID ||
                req.body.moduleId ||
                req.body.module_id;
    
            const password = req.body.password;
            const pqcSignature =
                req.body.pqcSignature ||
                req.body.pqc_signature ||
                null;
    
            const vehicleResetConfirmed =
                req.body.vehicleResetConfirmed === true ||
                req.body.vehicle_reset_confirmed === true;
    
            const reason =
                req.body.reason ||
                "Owner reset toàn bộ hệ thống";
    
            if (!rawModuleId) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    error: "moduleID là bắt buộc"
                });
            }
    
            if (!password) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    error: "Cần nhập mật khẩu tài khoản để xác nhận reset xe"
                });
            }
    
            if (!pqcSignature) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    error: "Thiếu chữ ký PQC xác nhận lệnh reset"
                });
            }
    
            if (!vehicleResetConfirmed) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    error: "Xe chưa xác nhận reset NVS thành công, chưa được đồng bộ Cloud"
                });
            }
    
            const moduleId = String(rawModuleId).trim().toLowerCase();
    
            // 1. Lấy thông tin Owner hiện tại
            const userResult = await client.query(
                `
                SELECT id, email, password_hash
                FROM users
                WHERE id = $1::uuid
                LIMIT 1
                `,
                [req.auth.userId]
            );
    
            if (userResult.rows.length === 0) {
                await client.query("ROLLBACK");
                return res.status(404).json({
                    error: "Không tìm thấy tài khoản Owner"
                });
            }
    
            const currentUser = userResult.rows[0];
    
            // 2. Xác thực mật khẩu Owner
            const passwordMatched = await bcrypt.compare(
                password,
                currentUser.password_hash
            );
    
            if (!passwordMatched) {
                await client.query("ROLLBACK");
                return res.status(401).json({
                    error: "Mật khẩu xác nhận không đúng"
                });
            }
    
            // 3. Kiểm tra Owner có OWNER key trên module này không
            const ownerKeyResult = await client.query(
                `
                SELECT *
                FROM digital_keys
                WHERE module_id = $1
                  AND owner_id = $2::uuid
                  AND holder_id = $2::uuid
                  AND role = 'OWNER'
                  AND state IN ('ACTIVE', 'PROVISIONING', 'SUSPENDED')
                LIMIT 1
                `,
                [moduleId, req.auth.userId]
            );
    
            if (ownerKeyResult.rows.length === 0) {
                await client.query("ROLLBACK");
                return res.status(403).json({
                    error: "Không tìm thấy OWNER key hợp lệ để reset hệ thống"
                });
            }
    
            const ownerKey = ownerKeyResult.rows[0];
    
            // 4. Lấy toàn bộ key thuộc module trước khi xóa để lưu lịch sử
            const allKeysResult = await client.query(
                `
                SELECT *
                FROM digital_keys
                WHERE module_id = $1
                  AND owner_id = $2::uuid
                ORDER BY created_at ASC
                `,
                [moduleId, req.auth.userId]
            );
    
            const allKeys = allKeysResult.rows;
    
            // 5. Lưu lịch sử revoke/reset cho từng key vào revoke_jobs
            const revokeJobs = [];
    
            for (const key of allKeys) {
                const jobResult = await client.query(
                    `
                    INSERT INTO revoke_jobs (
                        key_id,
                        module_id,
                        requester_id,
                        target_user_id,
                        status,
                        reason,
                        key_snapshot,
                        created_at,
                        updated_at
                    )
                    VALUES (
                        $1, $2,
                        $3::uuid,
                        $4::uuid,
                        'REVOKED',
                        $5,
                        $6,
                        CURRENT_TIMESTAMP,
                        CURRENT_TIMESTAMP
                    )
                    RETURNING *
                    `,
                    [
                        key.key_id,
                        key.module_id,
                        req.auth.userId,
                        key.holder_id,
                        reason,
                        key
                    ]
                );
    
                revokeJobs.push(jobResult.rows[0]);
            }
    
            // 6. Hủy các invitation còn pending/đang liên quan tới module
            const cancelledInvitationsResult = await client.query(
                `
                UPDATE key_invitations
                SET status = 'CANCELLED',
                    updated_at = CURRENT_TIMESTAMP
                WHERE module_id = $1
                  AND sender_id = $2::uuid
                  AND status IN ('PENDING')
                RETURNING *
                `,
                [moduleId, req.auth.userId]
            );
    
            // 7. Xóa toàn bộ digital key của module khỏi Cloud
            const deletedKeysResult = await client.query(
                `
                DELETE FROM digital_keys
                WHERE module_id = $1
                  AND owner_id = $2::uuid
                RETURNING *
                `,
                [moduleId, req.auth.userId]
            );
    
            // 8. Đưa xe/module về trạng thái UNPAIRED
            const vehicleResult = await client.query(
                `
                UPDATE vehicles
                SET status = 'UNPAIRED',
                    updated_at = CURRENT_TIMESTAMP
                WHERE module_id = $1
                  AND current_owner_id = $2::uuid
                RETURNING *
                `,
                [moduleId, req.auth.userId]
            );
    
            await client.query("COMMIT");
    
            return res.json({
                message: "Reset xe thành công. Cloud đã xóa toàn bộ khóa kỹ thuật số của module và đưa xe về trạng thái UNPAIRED.",
                moduleID: moduleId,
                vehicleState: "UNPAIRED",
                oledMessage: "VEHICLE IS UNPAIRED",
                deletedKeyCount: deletedKeysResult.rows.length,
                deletedKeys: deletedKeysResult.rows,
                cancelledInvitationCount: cancelledInvitationsResult.rows.length,
                cancelledInvitations: cancelledInvitationsResult.rows,
                revokeJobs,
                vehicle: vehicleResult.rows[0] || null,
                localAction: "Ứng dụng cần xóa dữ liệu khóa cục bộ trên điện thoại và quay về màn hình trống."
            });
        } catch (err) {
            await client.query("ROLLBACK");
    
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