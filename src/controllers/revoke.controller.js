const pool = require("../config/db");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFile } = require("child_process");
const { promisify } = require("util");
 
const execFileAsync = promisify(execFile);
 
function normalizeHex(value) {
    if (!value) return null;
    return String(value).trim().toLowerCase();
}
 
function normalizeEmail(value) {
    if (!value) return null;
    return String(value).trim().toLowerCase();
}
 
function normalizeIdentifier(value) {
    if (!value) return null;
    return String(value).trim();
}
 
function getModuleId(body) {
    return normalizeIdentifier(body.moduleID || body.moduleId || body.module_id);
}
 
function getKeyId(body) {
    return normalizeIdentifier(body.keyId || body.key_id || null);
}
 
function getSignature(body) {
    return body.pqcSignature || body.pqc_signature || body.ownerSignature || body.owner_signature || body.signature || null;
}
 
function getAttestation(body) {
    return body.revocationAttestation || body.revocation_attestation || body.vehicleAttestation || body.vehicle_attestation || null;
}
 
function isTrue(value) {
    return value === true || value === "true" || value === 1 || value === "1";
}
 
function verifyVehicleProvisionToken(req) {
    const expectedToken = process.env.VEHICLE_PROVISION_TOKEN;
 
    if (!expectedToken) {
        return true;
    }
 
    const receivedToken =
        req.headers["x-vehicle-provision-token"] ||
        req.headers["x-provision-token"];
 
    return receivedToken === expectedToken;
}
 
async function rollbackSafely(client) {
    try {
        await client.query("ROLLBACK");
    } catch (_) {
        // ignore rollback error, original error will be returned to client
    }
}
 
 
function sha256Hex(value) {
    return crypto
        .createHash("sha256")
        .update(String(value || ""), "utf8")
        .digest("hex");
}
 
function sortObject(value) {
    if (Array.isArray(value)) {
        return value.map(sortObject);
    }
 
    if (value && typeof value === "object") {
        return Object.keys(value)
            .sort()
            .reduce((result, key) => {
                result[key] = sortObject(value[key]);
                return result;
            }, {});
    }
 
    return value;
}
 
function canonicalize(value) {
    return JSON.stringify(sortObject(value));
}
 
function getDilithiumToolPath() {
    if (process.env.DILITHIUM3_TOOL_PATH) {
        return process.env.DILITHIUM3_TOOL_PATH;
    }
 
    const candidates = [
        path.join(process.cwd(), "dilithium", "ref", "tools", "dilithium3_tool.exe"),
        path.join(process.cwd(), "dilithium", "ref", "tools", "dilithium3_tool"),
        path.join(__dirname, "..", "..", "dilithium", "ref", "tools", "dilithium3_tool.exe"),
        path.join(__dirname, "..", "..", "dilithium", "ref", "tools", "dilithium3_tool")
    ];
 
    const found = candidates.find(candidate => fs.existsSync(candidate));
 
    if (found) {
        return found;
    }
 
    return path.join(process.cwd(), "dilithium", "ref", "tools", "dilithium3_tool");
}
 
function getCloudDilithiumKeyId() {
    return process.env.CLOUD_DILITHIUM_KEY_ID || "cloud-dilithium3-key-v1";
}
 
function getCloudDilithiumSecretKeyHex() {
    const key = process.env.CLOUD_DILITHIUM_SECRET_KEY_HEX;
 
    if (!key) {
        throw new Error("CLOUD_DILITHIUM_SECRET_KEY_HEX is missing");
    }
 
    return String(key).trim();
}
 
function getCloudDilithiumPublicKeyHex() {
    const key = process.env.CLOUD_DILITHIUM_PUBLIC_KEY_HEX;
 
    if (!key) {
        throw new Error("CLOUD_DILITHIUM_PUBLIC_KEY_HEX is missing");
    }
 
    return String(key).trim();
}
 
async function writeTempMessageFile(message) {
    const fileName = `revoke-payload-${crypto.randomUUID()}.json`;
    const filePath = path.join(os.tmpdir(), fileName);
 
    await fs.promises.writeFile(filePath, message, "utf8");
 
    return filePath;
}
 
async function signCloudRevokePayload(canonicalPayload) {
    const toolPath = getDilithiumToolPath();
    const secretKeyHex = getCloudDilithiumSecretKeyHex();
    const messagePath = await writeTempMessageFile(canonicalPayload);
 
    try {
        const { stdout } = await execFileAsync(
            toolPath,
            ["sign", secretKeyHex, messagePath],
            { maxBuffer: 1024 * 1024 * 20 }
        );
 
        return stdout.trim();
    } finally {
        await fs.promises.unlink(messagePath).catch(() => {});
    }
}
 
async function verifyCloudRevokePayload(canonicalPayload, signatureHex, publicKeyHex) {
    const toolPath = getDilithiumToolPath();
    const publicKey = publicKeyHex || getCloudDilithiumPublicKeyHex();
    const messagePath = await writeTempMessageFile(canonicalPayload);
 
    try {
        const { stdout } = await execFileAsync(
            toolPath,
            ["verify", publicKey, messagePath, signatureHex],
            { maxBuffer: 1024 * 1024 * 20 }
        );
 
        return stdout.trim() === "VALID";
    } catch (err) {
        if (err.stdout && String(err.stdout).trim() === "INVALID") {
            return false;
        }
 
        throw err;
    } finally {
        await fs.promises.unlink(messagePath).catch(() => {});
    }
}
 
function buildSignedCloudRevokePayload({ moduleId, ownerKeyId, revokeJobId, reason }) {
    const issuedAt = new Date();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
 
    return {
        type: "CLOUD_REVOKE_OWNER",
        command: "CMD_REVOKE_OWNER",
        moduleID: moduleId,
        ownerKeyId,
        revokeJobId,
        issuedAt: issuedAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
        nonce: crypto.randomBytes(16).toString("hex"),
        reasonHash: sha256Hex(reason),
        requireVehicleResult: true,
        sigAlg: "DILITHIUM3",
        sigAlgNote: "CRYSTALS-Dilithium3 round3; ML-DSA-65-compatible security level for project prototype",
        signerKeyId: getCloudDilithiumKeyId()
    };
}
 
module.exports = {
    /**
     * CASE 1.1 - Owner thu hồi Friend.
     * Server phase: Owner app đã/đang gửi INS_REMOVE_FRIEND tới xe qua BLE,
     * đồng thời gửi yêu cầu lên Cloud để chuyển Friend key sang REVOKED ngay.
     * revoke_jobs tách 2 job PENDING: Owner sync xuống xe và Friend soft-wipe local.
     */
    createFriendRevokeRequest: async (req, res) => {
        const client = await pool.connect();
 
        try {
            await client.query("BEGIN");
 
            const moduleId = getModuleId(req.body);
            const keyId = getKeyId(req.body);
            const friendEmail = normalizeEmail(
                req.body.friendEmail ||
                req.body.friend_email ||
                req.body.holderEmail ||
                req.body.holder_email ||
                null
            );
            const ownerSignature = getSignature(req.body);
            const reason = req.body.reason || "Owner revoked Friend key";
 
            if (!moduleId) {
                await rollbackSafely(client);
                return res.status(400).json({ error: "moduleID is required" });
            }
 
            if (!keyId && !friendEmail) {
                await rollbackSafely(client);
                return res.status(400).json({
                    error: "keyId or friendEmail is required to identify the Friend key"
                });
            }
 
            // Theo đặc tả, yêu cầu revoke Friend cần chữ ký của Owner.
            // Controller chỉ kiểm tra sự hiện diện; phần verify chữ ký PQC nên đặt trong crypto service/middleware.
            if (!ownerSignature) {
                await rollbackSafely(client);
                return res.status(400).json({
                    error: "Owner PQC signature is required for revoke request"
                });
            }
 
            const ownerKeyResult = await client.query(
                `
                SELECT id, key_id, module_id, owner_id, holder_id, role, state
                FROM public.digital_keys
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
                await rollbackSafely(client);
                return res.status(403).json({
                    error: "Current user does not have an ACTIVE OWNER key for this module"
                });
            }
 
            const friendKeyParams = keyId
                ? [keyId, moduleId, req.auth.userId]
                : [moduleId, req.auth.userId, friendEmail];
 
            const friendKeyResult = await client.query(
                keyId
                    ? `
                    SELECT dk.*, holder.email AS holder_email, holder.display_name AS holder_name
                    FROM public.digital_keys dk
                    JOIN public.users holder ON holder.id = dk.holder_id
                    WHERE dk.key_id = $1
                      AND dk.module_id = $2
                      AND dk.owner_id = $3::uuid
                      AND dk.role = 'FRIEND'
                      AND dk.state IN ('ACTIVE', 'PROVISIONING', 'SUSPENDED')
                    LIMIT 1
                    FOR UPDATE OF dk
                    `
                    : `
                    SELECT dk.*, holder.email AS holder_email, holder.display_name AS holder_name
                    FROM public.digital_keys dk
                    JOIN public.users holder ON holder.id = dk.holder_id
                    WHERE dk.module_id = $1
                      AND dk.owner_id = $2::uuid
                      AND LOWER(holder.email) = LOWER($3)
                      AND dk.role = 'FRIEND'
                      AND dk.state IN ('ACTIVE', 'PROVISIONING', 'SUSPENDED')
                    LIMIT 1
                    FOR UPDATE OF dk
                    `,
                friendKeyParams
            );
 
            if (friendKeyResult.rows.length === 0) {
                await rollbackSafely(client);
                return res.status(404).json({
                    error: "No active Friend key found for revoke"
                });
            }
 
            const friendKey = friendKeyResult.rows[0];
            const ownerKey = ownerKeyResult.rows[0];
 
            const existingJobResult = await client.query(
                `
                SELECT *
                FROM public.revoke_jobs
                WHERE key_id = $1
                  AND module_id = $2
                  AND status = 'PENDING'
                  AND job_type IN ('OWNER_VEHICLE_SYNC', 'FRIEND_LOCAL_WIPE')
                LIMIT 1
                `,
                [friendKey.key_id, friendKey.module_id]
            );
 
            if (existingJobResult.rows.length > 0) {
                await rollbackSafely(client);
                return res.status(409).json({
                    error: "Pending revoke jobs already exist for this Friend key",
                    revokeJob: existingJobResult.rows[0]
                });
            }
 
            const revokedKeyResult = await client.query(
                `
                UPDATE public.digital_keys
                SET state = 'REVOKED',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $1
                RETURNING *
                `,
                [friendKey.id]
            );
 
            const baseSnapshot = {
                ...friendKey,
                revoke_type: "OWNER_REVOKE_FRIEND",
                owner_key_id: ownerKey.key_id,
                owner_signature: ownerSignature
            };
 
            const ownerJobSnapshot = {
                ...baseSnapshot,
                job_type: "OWNER_VEHICLE_SYNC",
                task: "Owner app sends INS_REMOVE_FRIEND to vehicle via BLE and reports SYNCED/SUCCESS after vehicle confirmation."
            };
 
            const friendJobSnapshot = {
                ...baseSnapshot,
                job_type: "FRIEND_LOCAL_WIPE",
                task: "Friend app soft-wipes local key material and reports WIPED/SUCCESS after local cleanup."
            };
 
            const ownerJobResult = await client.query(
                `
                INSERT INTO public.revoke_jobs (
                    key_id,
                    module_id,
                    requester_id,
                    target_user_id,
                    job_type,
                    status,
                    reason,
                    key_snapshot,
                    created_at,
                    updated_at
                )
                VALUES (
                    $1, $2, $3::uuid, $4::uuid,
                    'OWNER_VEHICLE_SYNC',
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
                    req.auth.userId,
                    `${reason}; owner must sync revoke command to vehicle`,
                    ownerJobSnapshot
                ]
            );
 
            const friendJobResult = await client.query(
                `
                INSERT INTO public.revoke_jobs (
                    key_id,
                    module_id,
                    requester_id,
                    target_user_id,
                    job_type,
                    status,
                    reason,
                    key_snapshot,
                    created_at,
                    updated_at
                )
                VALUES (
                    $1, $2, $3::uuid, $4::uuid,
                    'FRIEND_LOCAL_WIPE',
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
                    `${reason}; friend must soft-wipe local key`,
                    friendJobSnapshot
                ]
            );
 
            await client.query("COMMIT");
 
            const revokedKey = revokedKeyResult.rows[0];
            const revokeJobs = [ownerJobResult.rows[0], friendJobResult.rows[0]];
 
            return res.status(201).json({
                success: true,
                message: "Friend key is REVOKED on Cloud. Pending jobs were created for Owner vehicle sync and Friend local soft-wipe.",
                flow: "OWNER_REVOKE_FRIEND",
                state: revokedKey.state,
                revokeJobs,
                ownerVehicleSyncJob: ownerJobResult.rows[0],
                friendLocalWipeJob: friendJobResult.rows[0],
                vehicleCommand: {
                    command: "INS_REMOVE_FRIEND",
                    transport: "BLE_FAST_ACTION",
                    payload: {
                        moduleID: revokedKey.module_id,
                        keyId: revokedKey.key_id
                    }
                },
                friendSoftWipe: {
                    targetUserId: friendKey.holder_id,
                    targetEmail: friendKey.holder_email,
                    keyId: revokedKey.key_id,
                    moduleID: revokedKey.module_id
                },
                friendKey: {
                    keyId: revokedKey.key_id,
                    moduleID: revokedKey.module_id,
                    holderEmail: friendKey.holder_email,
                    role: revokedKey.role,
                    state: revokedKey.state
                }
            });
        } catch (err) {
            await rollbackSafely(client);
 
            return res.status(500).json({
                error: err.message,
                detail: err.detail,
                hint: err.hint
            });
        } finally {
            client.release();
        }
    },
 
    /**
     * Owner/Friend lấy các revoke job đang PENDING.
     * - Owner chỉ thấy job OWNER_VEHICLE_SYNC của chính mình.
     * - Friend chỉ thấy job FRIEND_LOCAL_WIPE nhắm tới mình.
     */
    listMyRevokeJobs: async (req, res) => {
        try {
            const result = await pool.query(
                `
                SELECT
                    rj.id,
                    rj.key_id,
                    rj.module_id,
                    rj.job_type,
                    requester.email AS requester_email,
                    requester.display_name AS requester_name,
                    target.email AS target_email,
                    target.display_name AS target_name,
                    rj.status,
                    rj.reason,
                    rj.key_snapshot,
                    rj.failure_reason,
                    rj.synced_at,
                    rj.created_at,
                    rj.updated_at
                FROM public.revoke_jobs rj
                JOIN public.users requester ON requester.id = rj.requester_id
                JOIN public.users target ON target.id = rj.target_user_id
                WHERE rj.target_user_id = $1::uuid
                  AND rj.status = 'PENDING'
                ORDER BY rj.created_at DESC
                `,
                [req.auth.userId]
            );
 
            const jobs = result.rows.map(job => ({
                ...job,
                appAction: job.job_type === "OWNER_VEHICLE_SYNC"
                    ? {
                        action: "SEND_VEHICLE_COMMAND",
                        command: "INS_REMOVE_FRIEND",
                        transport: "BLE_FAST_ACTION",
                        payload: {
                            moduleID: job.module_id,
                            keyId: job.key_id
                        },
                        reportStatusAfterSuccess: "SYNCED"
                    }
                    : job.job_type === "FRIEND_LOCAL_WIPE"
                        ? {
                            action: "SOFT_WIPE_LOCAL_KEY",
                            payload: {
                                moduleID: job.module_id,
                                keyId: job.key_id
                            },
                            reportStatusAfterSuccess: "WIPED"
                        }
                        : null
            }));
 
            return res.json({
                success: true,
                count: jobs.length,
                jobs
            });
        } catch (err) {
            return res.status(500).json({
                error: err.message,
                detail: err.detail,
                hint: err.hint
            });
        }
    },
 
    /**
     * Báo cáo hoàn tất hoặc thất bại của revoke job.
     * Dùng cho cả xe đã xóa slot Friend và Friend app đã soft-wipe local.
     */
    reportRevokeJob: async (req, res) => {
        const client = await pool.connect();
 
        try {
            await client.query("BEGIN");
 
            const jobId = req.body.jobId || req.body.job_id || req.body.id;
            const status = req.body.status || "REVOKED";
            const failureReason =
                req.body.failureReason ||
                req.body.failure_reason ||
                req.body.error ||
                null;
 
            if (!jobId) {
                await rollbackSafely(client);
                return res.status(400).json({ error: "jobId is required" });
            }
 
            let normalizedStatus = String(status).trim().toUpperCase();
 
            if (["DONE", "ACCEPTED", "SYNCED", "SUCCESS", "WIPED"].includes(normalizedStatus)) {
                normalizedStatus = "REVOKED";
            }
 
            if (!["REVOKED", "FAILED"].includes(normalizedStatus)) {
                await rollbackSafely(client);
                return res.status(400).json({
                    error: "status must be REVOKED, DONE, ACCEPTED, SYNCED, SUCCESS, WIPED, or FAILED"
                });
            }
 
            const jobResult = await client.query(
                `
                SELECT *
                FROM revoke_jobs
                WHERE id = $1::uuid
                  AND target_user_id = $2::uuid
                  AND status = 'PENDING'
                LIMIT 1
                FOR UPDATE
                `,
                [jobId, req.auth.userId]
            );
 
            if (jobResult.rows.length === 0) {
                await rollbackSafely(client);
                return res.status(404).json({
                    error: "No pending revoke job found for current user"
                });
            }
 
            const job = jobResult.rows[0];
            let revokedKey = null;
 
            if (normalizedStatus === "REVOKED") {
                const revokedKeyResult = await client.query(
                    `
                    UPDATE public.digital_keys
                    SET state = 'REVOKED',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE key_id = $1
                      AND module_id = $2
                    RETURNING key_id, module_id, state, updated_at
                    `,
                    [job.key_id, job.module_id]
                );
 
                revokedKey = revokedKeyResult.rows[0] || {
                    key_id: job.key_id,
                    module_id: job.module_id,
                    state: "REVOKED"
                };
            }
 
            const updatedJobResult = await client.query(
                `
                UPDATE revoke_jobs
                SET status = $1::varchar,
                    failure_reason = $2,
                    synced_at = CASE
                        WHEN $1::varchar = 'REVOKED' THEN CURRENT_TIMESTAMP
                        ELSE synced_at
                    END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $3
                  AND target_user_id = $4::uuid
                RETURNING *
                `,
                [normalizedStatus, failureReason, jobId, req.auth.userId]
            );
 
            await client.query("COMMIT");
 
            return res.json({
                success: normalizedStatus === "REVOKED",
                message: normalizedStatus === "REVOKED"
                    ? "Revoke job completed. Cloud key state is REVOKED."
                    : "Revoke job failed. Cloud key remains REVOKED if it was already revoked.",
                revokeJob: updatedJobResult.rows[0],
                key: revokedKey
            });
        } catch (err) {
            await rollbackSafely(client);
 
            return res.status(500).json({
                error: err.message,
                detail: err.detail,
                hint: err.hint
            });
        } finally {
            client.release();
        }
    },
 
    /**
     * CASE 1.2 - Owner tự thu hồi / reset xe.
     * App chỉ gọi API này sau khi Standard Transaction CMD_REVOKE_OWNER qua BLE thành công
     * và xe đã xóa NVS, tránh trạng thái Cloud xóa trước nhưng xe vẫn còn key cục bộ.
     */
    revokeOwnerKey: async (req, res) => {
        const client = await pool.connect();
 
        try {
            await client.query("BEGIN");
 
            const moduleId = getModuleId(req.body);
            const password = req.body.password;
            const pqcSignature = getSignature(req.body);
            const vehicleResetConfirmed = isTrue(req.body.vehicleResetConfirmed) || isTrue(req.body.vehicle_reset_confirmed);
            const reason = req.body.reason || "Owner reset vehicle";
 
            if (!moduleId) {
                await rollbackSafely(client);
                return res.status(400).json({ error: "moduleID is required" });
            }
 
            if (!password) {
                await rollbackSafely(client);
                return res.status(400).json({
                    error: "Account password is required to confirm vehicle reset"
                });
            }
 
            if (!pqcSignature) {
                await rollbackSafely(client);
                return res.status(400).json({
                    error: "Missing PQC signature for CMD_REVOKE_OWNER"
                });
            }
 
            if (!vehicleResetConfirmed) {
                await rollbackSafely(client);
                return res.status(409).json({
                    error: "Vehicle has not confirmed NVS reset yet. Run CMD_REVOKE_OWNER via BLE first."
                });
            }
 
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
                await rollbackSafely(client);
                return res.status(404).json({ error: "Owner account not found" });
            }
 
            const passwordMatched = await bcrypt.compare(password, userResult.rows[0].password_hash);
 
            if (!passwordMatched) {
                await rollbackSafely(client);
                return res.status(401).json({
                    error: "Confirmation password is incorrect"
                });
            }
 
            const ownerKeyResult = await client.query(
                `
                SELECT *
                FROM public.digital_keys
                WHERE module_id = $1
                  AND owner_id = $2::uuid
                  AND holder_id = $2::uuid
                  AND role = 'OWNER'
                  AND state IN ('ACTIVE', 'PROVISIONING', 'SUSPENDED')
                LIMIT 1
                FOR UPDATE
                `,
                [moduleId, req.auth.userId]
            );
 
            if (ownerKeyResult.rows.length === 0) {
                await rollbackSafely(client);
                return res.status(403).json({
                    error: "No valid OWNER key found for vehicle reset"
                });
            }
 
            const allKeysResult = await client.query(
                `
                SELECT *
                FROM public.digital_keys
                WHERE module_id = $1
                  AND owner_id = $2::uuid
                ORDER BY created_at ASC
                FOR UPDATE
                `,
                [moduleId, req.auth.userId]
            );
 
            const revokeJobs = [];
 
            for (const key of allKeysResult.rows) {
                const jobStatus = key.role === "FRIEND" ? "PENDING" : "REVOKED";
                const syncedAtSql = jobStatus === "REVOKED" ? "CURRENT_TIMESTAMP" : "NULL";
                const jobReason = key.role === "FRIEND"
                    ? `${reason}; soft-wipe Friend local key after Owner reset`
                    : `${reason}; Owner local key already wiped after vehicle reset`;
 
                const keySnapshot = {
                    ...key,
                    revoke_type: "OWNER_SELF_RESET",
                    owner_signature: pqcSignature,
                    vehicle_reset_confirmed: true
                };
 
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
                        synced_at,
                        created_at,
                        updated_at
                    )
                    VALUES (
                        $1, $2,
                        $3::uuid,
                        $4::uuid,
                        $5,
                        $6,
                        $7,
                        ${syncedAtSql},
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
                        jobStatus,
                        jobReason,
                        keySnapshot
                    ]
                );
 
                revokeJobs.push(jobResult.rows[0]);
            }
 
            const cancelledInvitationsResult = await client.query(
                `
                UPDATE key_invitations
                SET status = 'CANCELLED',
                    updated_at = CURRENT_TIMESTAMP
                WHERE module_id = $1
                  AND sender_id = $2::uuid
                  AND status = 'PENDING'
                RETURNING *
                `,
                [moduleId, req.auth.userId]
            );
 
            const deletedKeysResult = await client.query(
                `
                DELETE FROM public.digital_keys
                WHERE module_id = $1
                  AND owner_id = $2::uuid
                RETURNING *
                `,
                [moduleId, req.auth.userId]
            );
 
            const vehicleResult = await client.query(
                `
                UPDATE public.vehicles
                SET status = 'UNPAIRED',
                    current_owner_id = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE module_id = $1
                  AND current_owner_id = $2::uuid
                RETURNING *
                `,
                [moduleId, req.auth.userId]
            );
 
            await client.query("COMMIT");
 
            return res.json({
                success: true,
                message: "Owner reset completed. Cloud removed all module keys, created Friend soft-wipe jobs, and marked the vehicle as UNPAIRED.",
                flow: "OWNER_SELF_RESET",
                moduleID: moduleId,
                vehicleState: "UNPAIRED",
                oledMessage: "VEHICLE IS UNPAIRED",
                deletedKeyCount: deletedKeysResult.rows.length,
                deletedKeys: deletedKeysResult.rows,
                pendingFriendWipeJobs: revokeJobs.filter(job => job.status === "PENDING"),
                revokeJobs,
                cancelledInvitationCount: cancelledInvitationsResult.rows.length,
                cancelledInvitations: cancelledInvitationsResult.rows,
                vehicle: vehicleResult.rows[0] || null,
                localAction: "Owner app should clear local key data only after this response succeeds. Friend apps will clear local keys from pending revoke jobs/push notification."
            });
        } catch (err) {
            await rollbackSafely(client);
 
            return res.status(500).json({
                error: err.message,
                detail: err.detail,
                hint: err.hint
            });
        } finally {
            client.release();
        }
    },
 
    /**
     * Public key để Vehicle/simulator pin khi verify lệnh revoke từ Cloud.
     * Lưu ý: public key không phải bí mật, nhưng private key CLOUD_DILITHIUM_SECRET_KEY_HEX tuyệt đối không được gửi ra client.
     */
    getCloudRevokeSigningPublicKey: async (req, res) => {
        try {
            return res.json({
                success: true,
                sigAlg: "DILITHIUM3",
                sigAlgNote: "CRYSTALS-Dilithium3 round3; dùng cho prototype tương ứng hướng ML-DSA-65",
                signerKeyId: getCloudDilithiumKeyId(),
                publicKeyHex: getCloudDilithiumPublicKeyHex()
            });
        } catch (err) {
            return res.status(500).json({
                error: err.message
            });
        }
    },
 
    /**
     * Endpoint test/debug: verify lại signedPayload + signature bằng Cloud public key.
     * Vehicle thật nên verify cục bộ bằng public key đã pin, không phụ thuộc endpoint này.
     */
    verifyCloudSignedRevokeCommand: async (req, res) => {
        try {
            const signedPayload = req.body.signedPayload || req.body.signed_payload || req.body.payload;
            const signature = req.body.signature || req.body.signatureHex || req.body.signature_hex;
 
            if (!signedPayload) {
                return res.status(400).json({ error: "signedPayload is required" });
            }
 
            if (!signature) {
                return res.status(400).json({ error: "signature is required" });
            }
 
            const canonicalPayload = canonicalize(signedPayload);
            const payloadHash = sha256Hex(canonicalPayload);
            const valid = await verifyCloudRevokePayload(canonicalPayload, signature);
 
            return res.json({
                success: true,
                valid,
                sigAlg: "DILITHIUM3",
                signerKeyId: getCloudDilithiumKeyId(),
                payloadHash
            });
        } catch (err) {
            return res.status(500).json({
                error: err.message,
                detail: err.detail,
                hint: err.hint
            });
        }
    },
 
    /**
     * CASE 2 - Cloud/Admin thu hồi Owner từ xa theo cơ chế status-based.
     * Server không gửi trực tiếp lệnh điều khiển xuống ESP32.
     * Server tạo revoke job PENDING và cập nhật vehicles.status = REVOKE_PENDING.
     * ESP32 sẽ đọc status của module xe, tự xóa local key/NVS, rồi báo SUCCESS/FAILED về Server.
     */
    createCloudOwnerRevokeRequestByModuleId: async (req, res) => {
        req.body.moduleID = req.params.moduleId;
        return module.exports.createCloudOwnerRevokeRequest(req, res);
    },
 
    createCloudOwnerRevokeRequest: async (req, res) => {
        const client = await pool.connect();
 
        try {
            await client.query("BEGIN");
 
            const moduleId = getModuleId(req.body);
            const ownerEmail = normalizeEmail(req.body.ownerEmail || req.body.owner_email || null);
            const reason = req.body.reason || "Cloud/Admin initiated Owner revocation";
 
            if (!moduleId) {
                await rollbackSafely(client);
                return res.status(400).json({
                    success: false,
                    error: "moduleID is required"
                });
            }
 
            const normalizedModuleId = String(moduleId).trim();
 
            const ownerKeyResult = await client.query(
                ownerEmail
                    ? `
                    SELECT dk.*, u.email AS owner_email
                    FROM public.users u
                    JOIN public.digital_keys dk
                      ON dk.owner_id = u.id
                     AND dk.holder_id = u.id
                    WHERE LOWER(dk.module_id) = LOWER($1)
                      AND LOWER(u.email) = LOWER($2)
                      AND dk.role = 'OWNER'
                      AND dk.state IN ('ACTIVE', 'PROVISIONING', 'SUSPENDED')
                    LIMIT 1
                    FOR UPDATE OF dk
                    `
                    : `
                    SELECT dk.*, u.email AS owner_email
                    FROM public.digital_keys dk
                    JOIN public.users u ON u.id = dk.holder_id
                    WHERE LOWER(dk.module_id) = LOWER($1)
                      AND dk.owner_id = dk.holder_id
                      AND dk.role = 'OWNER'
                      AND dk.state IN ('ACTIVE', 'PROVISIONING', 'SUSPENDED')
                    LIMIT 1
                    FOR UPDATE OF dk
                    `,
                ownerEmail ? [normalizedModuleId, ownerEmail] : [normalizedModuleId]
            );
 
            if (ownerKeyResult.rows.length === 0) {
                await rollbackSafely(client);
                return res.status(404).json({
                    success: false,
                    error: "No active OWNER key found for cloud revocation"
                });
            }
 
            const ownerKey = ownerKeyResult.rows[0];
 
            const existingJobResult = await client.query(
                `
                SELECT *
                FROM public.revoke_jobs
                WHERE LOWER(module_id) = LOWER($1)
                  AND target_user_id = $2::uuid
                  AND status = 'PENDING'
                LIMIT 1
                `,
                [ownerKey.module_id, ownerKey.holder_id]
            );
 
            if (existingJobResult.rows.length > 0) {
                await rollbackSafely(client);
                return res.status(409).json({
                    success: false,
                    error: "A pending cloud owner revoke job already exists for this module",
                    revokeJob: existingJobResult.rows[0]
                });
            }
 
            const jobResult = await client.query(
                `
                INSERT INTO public.revoke_jobs (
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
                    'PENDING',
                    $5,
                    $6,
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP
                )
                RETURNING *
                `,
                [
                    ownerKey.key_id,
                    ownerKey.module_id,
                    req.auth.userId,
                    ownerKey.holder_id,
                    reason,
                    {
                        ...ownerKey,
                        revoke_type: "CLOUD_REVOKE_OWNER",
                        vehicle_status_signal: "REVOKE_PENDING",
                        server_action: "SET_VEHICLE_STATUS_ONLY",
                        note: "Server does not send a signed command. ESP32 reads vehicle status and performs local revoke when status is REVOKE_PENDING."
                    }
                ]
            );
 
            const vehicleResult = await client.query(
                `
                UPDATE public.vehicles
                SET status = 'REVOKE_PENDING',
                    updated_at = CURRENT_TIMESTAMP
                WHERE LOWER(module_id) = LOWER($1)
                RETURNING *
                `,
                [ownerKey.module_id]
            );
 
            await client.query("COMMIT");
 
            return res.status(201).json({
                success: true,
                message: "Cloud owner revoke request created. Vehicle status is REVOKE_PENDING. Waiting for ESP32 to process local revoke and report SUCCESS/FAILED.",
                flow: "CLOUD_REVOKE_OWNER",
                moduleID: ownerKey.module_id,
                vehicleStatus: "REVOKE_PENDING",
                revokeJob: jobResult.rows[0],
                vehicle: vehicleResult.rows[0] || null,
                deviceAction: {
                    moduleID: ownerKey.module_id,
                    expectedVehicleStatus: "REVOKE_PENDING",
                    description: "ESP32 should read vehicle status, wipe Owner key, Friend keys, session keys and NVS data, then report SUCCESS or FAILED to Server."
                }
            });
        } catch (err) {
            await rollbackSafely(client);
 
            return res.status(500).json({
                success: false,
                error: err.message,
                detail: err.detail,
                hint: err.hint
            });
        } finally {
            client.release();
        }
    },
 
    /**
     * CASE 2 - ESP32 báo kết quả xử lý Cloud/Admin revoke Owner.
     * ESP32 chỉ gửi SUCCESS/FAILED sau khi đã tự xóa local key/NVS.
     * Nếu SUCCESS, Server mới xóa key trong DB và đưa xe về UNPAIRED.
     */
    completeCloudOwnerRevokeWithVehicleResult: async (req, res) => {
        const client = await pool.connect();
    
        try {
            if (!verifyVehicleProvisionToken(req)) {
                return res.status(401).json({
                    success: false,
                    error: "Invalid vehicle provision token"
                });
            }
 
            await client.query("BEGIN");
    
            const jobId = req.body.jobId || req.body.job_id || req.body.id;
            const moduleId = normalizeIdentifier(req.params.moduleId || getModuleId(req.body));
    
            const rawStatus =
                req.body.status ||
                req.body.result ||
                req.body.vehicleStatus ||
                req.body.vehicle_status;
    
            const vehicleMessage =
                req.body.message ||
                req.body.vehicleMessage ||
                req.body.vehicle_message ||
                req.body.error ||
                null;
    
            if (!jobId && !moduleId) {
                await rollbackSafely(client);
                return res.status(400).json({
                    success: false,
                    error: "jobId or moduleID is required"
                });
            }
 
            if (!rawStatus) {
                await rollbackSafely(client);
                return res.status(400).json({
                    success: false,
                    error: "status is required"
                });
            }
    
            const normalizedStatus = String(rawStatus).trim().toUpperCase();
    
            const isSuccess = ["SUCCESS", "DONE", "REVOKED", "OK", "WIPED"].includes(normalizedStatus);
            const isFailed = ["FAILED", "FAIL", "ERROR", "INVALID_SIGNATURE", "NVS_ERASE_FAILED", "LOCAL_KEY_NOT_FOUND"].includes(normalizedStatus);
    
            if (!isSuccess && !isFailed) {
                await rollbackSafely(client);
                return res.status(400).json({
                    success: false,
                    error: "status must be SUCCESS, DONE, REVOKED, OK, WIPED, FAILED, ERROR, INVALID_SIGNATURE, NVS_ERASE_FAILED, or LOCAL_KEY_NOT_FOUND"
                });
            }
    
            const jobResult = await client.query(
                `
                SELECT *
                FROM public.revoke_jobs
                WHERE status = 'PENDING'
                  AND ($1::text IS NULL OR id::text = $1::text)
                  AND ($2::text IS NULL OR LOWER(module_id) = LOWER($2))
                ORDER BY created_at DESC
                LIMIT 1
                FOR UPDATE
                `,
                [jobId || null, moduleId || null]
            );
    
            if (jobResult.rows.length === 0) {
                await rollbackSafely(client);
                return res.status(404).json({
                    success: false,
                    error: "No pending cloud owner revoke job found"
                });
            }
    
            const job = jobResult.rows[0];
    
            if (isFailed) {
                const failedJobResult = await client.query(
                    `
                    UPDATE public.revoke_jobs
                    SET status = 'FAILED',
                        failure_reason = $1,
                        key_snapshot = $2,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = $3
                    RETURNING *
                    `,
                    [
                        vehicleMessage || normalizedStatus,
                        {
                            ...(job.key_snapshot || {}),
                            revoke_type: "CLOUD_REVOKE_OWNER",
                            vehicle_result: {
                                status: "FAILED",
                                message: vehicleMessage || normalizedStatus,
                                received_at: new Date().toISOString()
                            }
                        },
                        job.id
                    ]
                );
    
                const vehicleResult = await client.query(
                    `
                    UPDATE public.vehicles
                    SET status = 'REVOKE_FAILED',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE LOWER(module_id) = LOWER($1)
                    RETURNING *
                    `,
                    [job.module_id]
                );
 
                await client.query("COMMIT");
    
                return res.status(409).json({
                    success: false,
                    message: "Vehicle reported cloud owner revocation failed. Cloud DB keys were not removed.",
                    flow: "CLOUD_REVOKE_OWNER",
                    moduleID: job.module_id,
                    revokeJob: failedJobResult.rows[0],
                    vehicleResult: {
                        status: "FAILED",
                        message: vehicleMessage || normalizedStatus
                    },
                    vehicle: vehicleResult.rows[0] || null
                });
            }
    
            const allKeysResult = await client.query(
                `
                SELECT *
                FROM public.digital_keys
                WHERE module_id = $1
                  AND owner_id = $2::uuid
                ORDER BY created_at ASC
                FOR UPDATE
                `,
                [job.module_id, job.target_user_id]
            );
    
            const deletedKeysResult = await client.query(
                `
                DELETE FROM public.digital_keys
                WHERE module_id = $1
                  AND owner_id = $2::uuid
                RETURNING *
                `,
                [job.module_id, job.target_user_id]
            );
    
            const vehicleResult = await client.query(
                `
                UPDATE public.vehicles
                SET status = 'UNPAIRED',
                    current_owner_id = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE module_id = $1
                RETURNING *
                `,
                [job.module_id]
            );
    
            const updatedJobResult = await client.query(
                `
                UPDATE public.revoke_jobs
                SET status = 'REVOKED',
                    key_snapshot = $1,
                    synced_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $2
                RETURNING *
                `,
                [
                    {
                        ...(job.key_snapshot || {}),
                        revoke_type: "CLOUD_REVOKE_OWNER",
                        vehicle_result: {
                            status: "SUCCESS",
                            message: vehicleMessage || "Vehicle keys removed successfully",
                            received_at: new Date().toISOString()
                        },
                        deleted_keys: allKeysResult.rows
                    },
                    job.id
                ]
            );
    
            await client.query("COMMIT");
    
            return res.json({
                success: true,
                message: "Vehicle reported revoke success. Cloud removed Owner/Friend keys and marked vehicle as UNPAIRED.",
                flow: "CLOUD_REVOKE_OWNER",
                moduleID: job.module_id,
                revokeJob: updatedJobResult.rows[0],
                vehicleResult: {
                    status: "SUCCESS",
                    message: vehicleMessage || "Vehicle keys removed successfully"
                },
                deletedKeyCount: deletedKeysResult.rows.length,
                deletedKeys: deletedKeysResult.rows,
                vehicle: vehicleResult.rows[0] || null,
                ownerPushPayload: {
                    type: "OWNER_REVOKE_RESULT",
                    moduleID: job.module_id,
                    status: "SUCCESS",
                    message: "Vehicle keys removed successfully"
                }
            });
        } catch (err) {
            await rollbackSafely(client);
    
            return res.status(500).json({
                success: false,
                error: err.message,
                detail: err.detail,
                hint: err.hint
            });
        } finally {
            client.release();
        }
    }
};
