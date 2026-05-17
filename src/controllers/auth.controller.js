const pool = require("../config/db");
const { hashPassword, comparePassword } = require("../utils/password");
const { signAccessToken, signRefreshToken, verifyRefreshToken } = require("../utils/jwt");


module.exports = {
    register: async (req, res) => {
        const client = await pool.connect();

        try {
            const {
                email,
                password,
                displayName,
                identity_pk,
                deviceName,
                fcmToken,
            } = req.body;

            if (!email || !password || !displayName || !identity_pk) {
                return res.status(400).json({
                    error: "email, password, displayName, identity_pk là bắt buộc",
                });
            }

            const normalizedEmail = email.trim().toLowerCase();

            await client.query("BEGIN");

            const existingUser = await client.query(
                "SELECT id FROM users WHERE email = $1",
                [normalizedEmail]
            );

            if (existingUser.rows.length > 0) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    error: "Email đã được sử dụng",
                });
            }

            const passwordHash = await hashPassword(password);

            const userResult = await client.query(
                `
                INSERT INTO users (email, password_hash, display_name, role)
                VALUES ($1, $2, $3, 'USER')
                RETURNING id, email, display_name, role, created_at
                `,
                [normalizedEmail, passwordHash, displayName]
            );

            const user = userResult.rows[0];

            const deviceResult = await client.query(
                `
                INSERT INTO user_devices (user_id, identity_pk, device_name, fcm_token)
                VALUES ($1, $2, $3, $4)
                RETURNING id, user_id, identity_pk, device_name, fcm_token, last_active
                `,
                [
                    user.id,
                    identity_pk.trim().toLowerCase(),
                    deviceName || null,
                    fcmToken || null,
                ]
            );

            await client.query("COMMIT");

            const accessToken = signAccessToken(user);
            const refreshToken = signRefreshToken(user);

            return res.status(201).json({
                message: "Đăng ký tài khoản thành công",
                accessToken,
                refreshToken,
                user,
                device: deviceResult.rows[0],
            });
        } catch (err) {
            await client.query("ROLLBACK");
            return res.status(500).json({
                error: err.message,
            });
        } finally {
            client.release();
        }
    },

    login: async (req, res) => {
        try {
            const { email, password, identity_pk, deviceName, fcmToken } = req.body;

            if (!email || !password) {
                return res.status(400).json({
                    error: "email và password là bắt buộc",
                });
            }

            const normalizedEmail = email.trim().toLowerCase();

            const userResult = await pool.query(
                `
                SELECT id, email, password_hash, display_name, role, created_at
                FROM users
                WHERE email = $1
                `,
                [normalizedEmail]
            );

            if (userResult.rows.length === 0) {
                return res.status(400).json({
                    error: "Email hoặc mật khẩu không đúng",
                });
            }

            const user = userResult.rows[0];

            const isMatch = await comparePassword(password, user.password_hash);

            if (!isMatch) {
                return res.status(400).json({
                    error: "Email hoặc mật khẩu không đúng",
                });
            }

            let device = null;

            if (identity_pk) {
                const deviceResult = await pool.query(
                    `
                    INSERT INTO user_devices (user_id, identity_pk, device_name, fcm_token, last_active)
                    VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
                    ON CONFLICT (user_id, identity_pk)
                    DO UPDATE SET
                        device_name = COALESCE(EXCLUDED.device_name, user_devices.device_name),
                        fcm_token = COALESCE(EXCLUDED.fcm_token, user_devices.fcm_token),
                        last_active = CURRENT_TIMESTAMP
                    RETURNING id, user_id, identity_pk, device_name, fcm_token, last_active
                    `,
                    [
                        user.id,
                        identity_pk.trim().toLowerCase(),
                        deviceName || null,
                        fcmToken || null,
                    ]
                );

                device = deviceResult.rows[0];
            }

            delete user.password_hash;

            const accessToken = signAccessToken(user);
            const refreshToken = signRefreshToken(user);

            return res.json({
                message: "Đăng nhập thành công",
                accessToken,
                refreshToken,
                user,
                device,
            });
        } catch (err) {
            return res.status(500).json({
                error: err.message,
            });
        }
    },

    updateFcmToken: async (req, res) => {
        try {
            const { identity_pk, fcmToken } = req.body;

            if (!identity_pk || !fcmToken) {
                return res.status(400).json({
                    error: "identity_pk và fcmToken là bắt buộc",
                });
            }

            const result = await pool.query(
                `
                UPDATE user_devices
                SET fcm_token = $1,
                    last_active = CURRENT_TIMESTAMP
                WHERE user_id = $2
                  AND identity_pk = $3
                RETURNING id, user_id, identity_pk, device_name, fcm_token, last_active
                `,
                [
                    fcmToken,
                    req.auth.userId,
                    identity_pk.trim().toLowerCase(),
                ]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    error: "Không tìm thấy thiết bị của user hiện tại",
                });
            }

            return res.json({
                message: "Cập nhật FCM token thành công",
                device: result.rows[0],
            });
        } catch (err) {
            return res.status(500).json({
                error: err.message,
            });
        }
    },

    me: async (req, res) => {
        try {
            const userResult = await pool.query(
                `
                SELECT id, email, display_name, role, created_at, updated_at
                FROM users
                WHERE id = $1
                `,
                [req.auth.userId]
            );

            if (userResult.rows.length === 0) {
                return res.status(404).json({
                    error: "User not found",
                });
            }

            const devicesResult = await pool.query(
                `
                SELECT id, identity_pk, device_name, fcm_token, last_active, created_at
                FROM user_devices
                WHERE user_id = $1
                ORDER BY last_active DESC
                `,
                [req.auth.userId]
            );

            return res.json({
                user: userResult.rows[0],
                devices: devicesResult.rows,
            });
        } catch (err) {
            return res.status(500).json({
                error: err.message,
            });
        }
    },
    refreshToken: async (req, res) => {
        try {
            const { refreshToken } = req.body;
    
            if (!refreshToken) {
                return res.status(400).json({
                    error: "refreshToken là bắt buộc"
                });
            }
    
            let decoded;
    
            try {
                decoded = verifyRefreshToken(refreshToken);
            } catch (err) {
                return res.status(401).json({
                    error: "Refresh token không hợp lệ hoặc đã hết hạn"
                });
            }
    
            const userResult = await pool.query(
                `
                SELECT id, email, display_name, role, created_at
                FROM users
                WHERE id = $1
                `,
                [decoded.userId]
            );
    
            if (userResult.rows.length === 0) {
                return res.status(404).json({
                    error: "User not found"
                });
            }
    
            const user = userResult.rows[0];
    
            const newAccessToken = signAccessToken(user);
    
            return res.json({
                message: "Cấp lại access token thành công",
                accessToken: newAccessToken,
                user
            });
        } catch (err) {
            return res.status(500).json({
                error: err.message
            });
        }
    },
};