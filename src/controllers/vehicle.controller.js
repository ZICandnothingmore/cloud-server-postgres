const pool = require("../config/db");
 
function normalizeIdentifier(value) {
    if (!value) return null;
    return String(value).trim();
}
 
function normalizeHex(value) {
    if (!value) return null;
    return String(value).trim().toLowerCase();
}
 
function getModuleId(body) {
    return normalizeIdentifier(body.moduleID || body.moduleId || body.module_id);
}
 
function isHexString(value) {
    return typeof value === "string" && /^[0-9a-fA-F]+$/.test(value);
}
 
function getCloudDilithiumKeyId() {
    return process.env.CLOUD_DILITHIUM_KEY_ID || "cloud-dilithium3-key-v1";
}
 
function getCloudDilithiumPublicKeyHex() {
    const key = process.env.CLOUD_DILITHIUM_PUBLIC_KEY_HEX;
 
    if (!key) {
        throw new Error("CLOUD_DILITHIUM_PUBLIC_KEY_HEX is missing");
    }
 
    return String(key).trim();
}
 
function verifyProvisionToken(req) {
    const expectedToken = process.env.VEHICLE_PROVISION_TOKEN;

    const receivedToken =
        req.headers["x-vehicle-provision-token"] ||
        req.headers["x-provision-token"];

    console.log("===== VERIFY PROVISION TOKEN =====");
    console.log("expectedToken:", expectedToken);
    console.log("receivedToken:", receivedToken);
    console.log("receivedToken === expectedToken:", receivedToken === expectedToken);
    console.log("headers:", {
        "x-provision-token": req.headers["x-provision-token"],
        "x-vehicle-provision-token": req.headers["x-vehicle-provision-token"],
    });
    console.log("==================================");

    if (!expectedToken) {
        return false;
    }

    if (!receivedToken) {
        return false;
    }

    return String(receivedToken).trim() === String(expectedToken).trim();
}
 
async function rollbackSafely(client) {
    try {
        await client.query("ROLLBACK");
    } catch (_) {
        // ignore rollback error
    }
}
 
module.exports = {
    registerVehicle: async (req, res) => {
        const client = await pool.connect();
 
        try {
            await client.query("BEGIN");
 
            const {
                module_id,
                moduleID,
                moduleId,
                vin,
                vehicle_identity_pk,
                vehicleIdentityPk,
                vehiclePublicKey,
                vehicleName
            } = req.body;
 
            const rawModuleId = module_id || moduleID || moduleId;
            const rawVehiclePk = vehicle_identity_pk || vehicleIdentityPk || vehiclePublicKey || null;
 
            if (!rawModuleId) {
                await rollbackSafely(client);
                return res.status(400).json({
                    error: "module_id/moduleID là bắt buộc"
                });
            }
 
            const normalizedModuleId = rawModuleId.trim();
            const normalizedVehiclePk = rawVehiclePk
                ? rawVehiclePk.trim().toLowerCase()
                : null;
 
            if (normalizedVehiclePk && !isHexString(normalizedVehiclePk)) {
                await rollbackSafely(client);
                return res.status(400).json({
                    error: "vehicle_identity_pk/vehiclePublicKey phải là chuỗi hex"
                });
            }
 
            const exists = await client.query(
                "SELECT module_id FROM public.vehicles WHERE LOWER(module_id) = LOWER($1)",
                [normalizedModuleId]
            );
 
            if (exists.rows.length > 0) {
                await rollbackSafely(client);
                return res.status(400).json({
                    error: "Module/Vehicle đã tồn tại"
                });
            }
 
            const result = await client.query(
                `
                INSERT INTO public.vehicles (
                    module_id,
                    vin,
                    vehicle_identity_pk,
                    current_owner_id,
                    vehicle_name,
                    status,
                    created_at,
                    updated_at
                )
                VALUES ($1, $2, $3, $4, $5, 'UNPAIRED', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                RETURNING *
                `,
                [
                    normalizedModuleId,
                    vin || null,
                    normalizedVehiclePk,
                    req.auth.userId,
                    vehicleName || null
                ]
            );
 
            await client.query(
                `
                INSERT INTO public.vehicle_users (
                    module_id,
                    user_id,
                    role,
                    status
                )
                VALUES ($1, $2, 'OWNER', 'ACTIVE')
                ON CONFLICT (module_id, user_id)
                DO UPDATE SET
                    role = 'OWNER',
                    status = 'ACTIVE',
                    linked_at = CURRENT_TIMESTAMP
                `,
                [
                    normalizedModuleId,
                    req.auth.userId
                ]
            );
 
            await client.query("COMMIT");
 
            return res.status(201).json({
                message: "Đăng ký module/vehicle thành công",
                vehicle: {
                    ...result.rows[0],
                    role: "OWNER",
                    user_vehicle_status: "ACTIVE"
                }
            });
        } catch (err) {
            await rollbackSafely(client);
 
            if (err.code === "23505") {
                return res.status(400).json({
                    error: "VIN hoặc module_id đã tồn tại"
                });
            }
 
            return res.status(500).json({
                error: err.message,
                detail: err.detail,
                hint: err.hint
            });
        } finally {
            client.release();
        }
    },
 
    registerVehicleIdentity: async (req, res) => {
        const client = await pool.connect();
 
        try {
            if (!verifyProvisionToken(req)) {
                return res.status(401).json({
                    success: false,
                    error: "Invalid vehicle provision token"
                });
            }
 
            const moduleId = getModuleId(req.body);
            const vehiclePublicKey = normalizeHex(
                req.body.vehiclePublicKey ||
                req.body.vehicle_public_key ||
                req.body.publicKey ||
                req.body.public_key
            );
 
            if (!moduleId) {
                return res.status(400).json({
                    success: false,
                    error: "moduleID is required"
                });
            }
 
            if (!vehiclePublicKey) {
                return res.status(400).json({
                    success: false,
                    error: "vehiclePublicKey is required"
                });
            }
 
            if (!isHexString(vehiclePublicKey)) {
                return res.status(400).json({
                    success: false,
                    error: "vehiclePublicKey must be a hex string"
                });
            }
 
            const normalizedModuleId = moduleId.trim();
            const serverPublicKey = getCloudDilithiumPublicKeyHex();
            const serverKeyId = getCloudDilithiumKeyId();
 
            await client.query("BEGIN");
 
            const vehicleResult = await client.query(
                `
                SELECT module_id, status
                FROM public.vehicles
                WHERE LOWER(module_id) = LOWER($1)
                LIMIT 1
                FOR UPDATE
                `,
                [normalizedModuleId]
            );
 
            if (vehicleResult.rows.length === 0) {
                await rollbackSafely(client);
                return res.status(404).json({
                    success: false,
                    error: "Vehicle moduleID not found"
                });
            }
 
            const storedModuleId = vehicleResult.rows[0].module_id;
 
            await client.query(
                `
                UPDATE public.vehicles
                SET vehicle_identity_pk = $1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE module_id = $2
                `,
                [
                    vehiclePublicKey,
                    storedModuleId
                ]
            );
 
            await client.query("COMMIT");
 
            return res.status(200).json({
                moduleID: storedModuleId,
                serverIdentity: {
                    serverPublicKey,
                    serverKeyId
                },
                vehicleIdentity: {
                    registered: true
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
 
    getVehicleStatusForDevice: async (req, res) => {
        try {
            if (!verifyProvisionToken(req)) {
                return res.status(401).json({
                    success: false,
                    error: "Invalid vehicle provision token"
                });
            }
 
            const moduleId = normalizeIdentifier(
                req.params.moduleId ||
                getModuleId(req.body) ||
                req.query.moduleID ||
                req.query.moduleId ||
                req.query.module_id
            );
 
            if (!moduleId) {
                return res.status(400).json({
                    success: false,
                    error: "moduleID is required"
                });
            }
 
            const normalizedModuleId = String(moduleId).trim();
 
            const result = await pool.query(
                `
                SELECT
                    module_id,
                    status,
                    vehicle_identity_pk,
                    current_owner_id,
                    vehicle_name,
                    updated_at
                FROM public.vehicles
                WHERE LOWER(module_id) = LOWER($1)
                LIMIT 1
                `,
                [normalizedModuleId]
            );
 
            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    error: "Vehicle moduleID not found"
                });
            }
 
            const vehicle = result.rows[0];
            const normalizedStatus = String(vehicle.status || "").toUpperCase();
            const shouldRevoke = normalizedStatus === "REVOKE_PENDING";
 
            return res.json({
                success: true,
                moduleID: vehicle.module_id,
                status: vehicle.status,
                registeredIdentity: !!vehicle.vehicle_identity_pk,
                action: shouldRevoke
                    ? {
                        required: true,
                        type: "CLOUD_REVOKE_OWNER",
                        command: "CMD_REVOKE_OWNER",
                        description: "ESP32 should wipe Owner key, Friend keys, session keys, and local NVS data, then report SUCCESS or FAILED to Server."
                    }
                    : {
                        required: false
                    },
                vehicle: {
                    moduleID: vehicle.module_id,
                    vehicleName: vehicle.vehicle_name,
                    status: vehicle.status,
                    updatedAt: vehicle.updated_at
                }
            });
        } catch (err) {
            return res.status(500).json({
                success: false,
                error: err.message,
                detail: err.detail,
                hint: err.hint
            });
        }
    },
 
    getMyModules: async (req, res) => {
        try {
            const result = await pool.query(
                `
                SELECT
                    v.*,
                    dk.role,
                    dk.state AS user_vehicle_status,
                    dk.created_at AS linked_at,
                    dk.key_id
                FROM public.digital_keys dk
                JOIN public.vehicles v
                    ON dk.module_id = v.module_id
                WHERE dk.holder_id = $1
                  AND dk.state = 'ACTIVE'
                ORDER BY dk.created_at DESC
                `,
                [req.auth.userId]
            );
    
            return res.json({
                vehicles: result.rows
            });
        } catch (err) {
            console.error("getMyModules error:", err);
    
            return res.status(500).json({
                error: err.message,
                detail: err.detail,
                hint: err.hint,
                code: err.code
            });
        }
    },
 
    getVehicleDetail: async (req, res) => {
        try {
            const { moduleId } = req.params;
            const normalizedModuleId = moduleId.trim();
 
            const result = await pool.query(
                `
                SELECT
                    v.*,
                    vu.role,
                    vu.status AS user_vehicle_status,
                    vu.linked_at
                FROM public.vehicles v
                JOIN public.vehicle_users vu
                    ON vu.module_id = v.module_id
                WHERE LOWER(v.module_id) = LOWER($1)
                  AND vu.user_id = $2
                  AND vu.status = 'ACTIVE'
                LIMIT 1
                `,
                [
                    normalizedModuleId,
                    req.auth.userId
                ]
            );
 
            if (result.rows.length === 0) {
                return res.status(404).json({
                    error: "Vehicle/Module không tồn tại hoặc bạn chưa có quyền truy cập"
                });
            }
 
            return res.json({
                vehicle: result.rows[0]
            });
        } catch (err) {
            return res.status(500).json({
                error: err.message
            });
        }
    }
};
