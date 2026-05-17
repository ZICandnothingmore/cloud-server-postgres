const pool = require("../config/db");

module.exports = {
    registerVehicle: async (req, res) => {
        try {
            const {
                module_id,
                vin,
                vehicle_identity_pk,
                vehicleName
            } = req.body;

            if (!module_id || !vehicle_identity_pk) {
                return res.status(400).json({
                    error: "module_id và vehicle_identity_pk là bắt buộc"
                });
            }

            const normalizedModuleId = module_id.trim().toLowerCase();
            const normalizedVehiclePk = vehicle_identity_pk.trim().toLowerCase();

            const exists = await pool.query(
                "SELECT module_id FROM vehicles WHERE module_id = $1",
                [normalizedModuleId]
            );

            if (exists.rows.length > 0) {
                return res.status(400).json({
                    error: "Module/Vehicle đã tồn tại"
                });
            }

            const result = await pool.query(
                `
                INSERT INTO vehicles (
                    module_id,
                    vin,
                    vehicle_identity_pk,
                    current_owner_id,
                    vehicle_name
                )
                VALUES ($1, $2, $3, $4, $5)
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

            await pool.query(
                `
                VALUES ($1, $2, 'OWNER', 'ACTIVE')
                ON CONFLICT (module_id, user_id)
                DO UPDATE SET
                    role = 'OWNER',
                    status = 'ACTIVE'
                `,
                [
                    normalizedModuleId,
                    req.auth.userId
                ]
            );

            return res.status(201).json({
                message: "Đăng ký module/vehicle thành công",
                vehicle: {
                    ...result.rows[0],
                    role: "OWNER",
                    user_vehicle_status: "ACTIVE"
                }
            });
        } catch (err) {
            if (err.code === "23505") {
                return res.status(400).json({
                    error: "VIN hoặc module_id đã tồn tại"
                });
            }

            return res.status(500).json({
                error: err.message
            });
        }
    },

    getMyModules: async (req, res) => {
        try {
            const result = await pool.query(
                `
                SELECT 
                    v.*,
                    vu.role,
                    vu.status AS user_vehicle_status,
                    vu.linked_at
                FROM vehicle_users vu
                JOIN vehicles v 
                    ON vu.module_id = v.module_id
                WHERE vu.user_id = $1
                  AND vu.status = 'ACTIVE'
                ORDER BY vu.linked_at DESC
                `,
                [req.auth.userId]
            );

            return res.json({
                vehicles: result.rows
            });
        } catch (err) {
            return res.status(500).json({
                error: err.message
            });
        }
    },

    getVehicleDetail: async (req, res) => {
        try {
            const { moduleId } = req.params;

            const normalizedModuleId = moduleId.trim().toLowerCase();

            const result = await pool.query(
                `
                VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
                ON CONFLICT (module_id, user_id)
                DO UPDATE SET
                    role = EXCLUDED.role,
                    status = EXCLUDED.status,
                    linked_at = CURRENT_TIMESTAMP
                `,
                [
                    normalizedModuleId,
                    req.auth.userId,
                    normalizedRole,
                    normalizedState
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