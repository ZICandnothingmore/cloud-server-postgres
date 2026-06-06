const pool = require("../config/db");
const { hashPassword, comparePassword } = require("../utils/password");
const {
    signAccessToken,
    signRefreshToken,
    verifyRefreshToken,
} = require("../utils/jwt");

function normalizeEmail(email) {
    return String(email || "").trim().toLowerCase();
}

function normalizeIdentityPk(identityPk) {
    return String(identityPk || "").trim().toLowerCase();
}

function getCloudPublicKey() {
    return process.env.CLOUD_DILITHIUM_PUBLIC_KEY_HEX || null;
}

function sanitizeUser(user) {
    if (!user) return null;

    const safeUser = { ...user };

    delete safeUser.password_hash;

    return safeUser;
}

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
    
            if (!email || !password) {
                return res.status(400).json({
                    error: "email và password là bắt buộc",
                });
            }
    
            const normalizedEmail = normalizeEmail(email);
            const finalDisplayName = getDisplayName(displayName, normalizedEmail);
    
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
                [normalizedEmail, passwordHash, finalDisplayName]
            );
    
            const user = userResult.rows[0];
    
            let device = null;
    
            if (identity_pk) {
                const normalizedIdentityPk = normalizeIdentityPk(identity_pk);
    
                const deviceResult = await client.query(
                    `
                    INSERT INTO user_devices (
                        user_id,
                        identity_pk,
                        device_name,
                        fcm_token,
                        last_active
                    )
                    VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
                    RETURNING
                        id,
                        user_id,
                        identity_pk,
                        device_name,
                        fcm_token,
                        last_active,
                        created_at
                    `,
                    [
                        user.id,
                        normalizedIdentityPk,
                        deviceName || null,
                        fcmToken || null,
                    ]
                );
    
                device = deviceResult.rows[0];
            }
    
            await client.query("COMMIT");
    
            const accessToken = signAccessToken(user);
            const refreshToken = signRefreshToken(user);
    
            return res.status(201).json({
                message: "Tạo tài khoản thành công",
                accessToken,
                refreshToken,
                user,
                device,
                cloudPublicKey: getCloudPublicKey(),
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
        const client = await pool.connect();

        try {
            const {
                email,
                password,
                identity_pk,
                deviceName,
                fcmToken,
            } = req.body;

            if (!email || !password || !identity_pk) {
                return res.status(400).json({
                    error: "email, password và identity_pk là bắt buộc",
                });
            }

            const normalizedEmail = normalizeEmail(email);
            const normalizedIdentityPk = normalizeIdentityPk(identity_pk);

            await client.query("BEGIN");

            const userResult = await client.query(
                `
                SELECT id, email, password_hash, display_name, role, created_at
                FROM users
                WHERE email = $1
                FOR UPDATE
                `,
                [normalizedEmail]
            );

            if (userResult.rows.length === 0) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    error: "Email hoặc mật khẩu không đúng",
                });
            }

            const user = userResult.rows[0];

            const isMatch = await comparePassword(password, user.password_hash);

            if (!isMatch) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    error: "Email hoặc mật khẩu không đúng",
                });
            }

            const deviceResult = await client.query(
                `
                SELECT
                    id,
                    user_id,
                    identity_pk,
                    device_name,
                    fcm_token,
                    last_active,
                    created_at
                FROM user_devices
                WHERE user_id = $1
                  AND identity_pk = $2
                LIMIT 1
                `,
                [user.id, normalizedIdentityPk]
            );

            let device = null;

            if (deviceResult.rows.length > 0) {
                const updatedDeviceResult = await client.query(
                    `
                    UPDATE user_devices
                    SET device_name = COALESCE($1, device_name),
                        fcm_token = COALESCE($2, fcm_token),
                        last_active = CURRENT_TIMESTAMP
                    WHERE user_id = $3
                      AND identity_pk = $4
                    RETURNING
                        id,
                        user_id,
                        identity_pk,
                        device_name,
                        fcm_token,
                        last_active,
                        created_at
                    `,
                    [
                        deviceName || null,
                        fcmToken || null,
                        user.id,
                        normalizedIdentityPk,
                    ]
                );

                device = updatedDeviceResult.rows[0];
            } else {
                const deviceCountResult = await client.query(
                    `
                    SELECT COUNT(*)::int AS count
                    FROM user_devices
                    WHERE user_id = $1
                    `,
                    [user.id]
                );

                const deviceCount = deviceCountResult.rows[0].count;

                if (deviceCount > 0) {
                    await client.query("ROLLBACK");
                    return res.status(403).json({
                        error: "Thiết bị không hợp lệ",
                        detail: "Public key của thiết bị không khớp với tài khoản",
                    });
                }

                const createdDeviceResult = await client.query(
                    `
                    INSERT INTO user_devices (
                        user_id,
                        identity_pk,
                        device_name,
                        fcm_token,
                        last_active
                    )
                    VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
                    RETURNING
                        id,
                        user_id,
                        identity_pk,
                        device_name,
                        fcm_token,
                        last_active,
                        created_at
                    `,
                    [
                        user.id,
                        normalizedIdentityPk,
                        deviceName || null,
                        fcmToken || null,
                    ]
                );

                device = createdDeviceResult.rows[0];
            }

            await client.query("COMMIT");

            const safeUser = sanitizeUser(user);

            const accessToken = signAccessToken(safeUser);
            const refreshToken = signRefreshToken(safeUser);

            return res.json({
                message: "Đăng nhập thành công",
                accessToken,
                refreshToken,
                user: safeUser,
                device,
                cloudPublicKey: getCloudPublicKey(),
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
                RETURNING
                    id,
                    user_id,
                    identity_pk,
                    device_name,
                    fcm_token,
                    last_active,
                    created_at
                `,
                [
                    fcmToken,
                    req.auth.userId,
                    normalizeIdentityPk(identity_pk),
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
                SELECT
                    id,
                    identity_pk,
                    device_name,
                    fcm_token,
                    last_active,
                    created_at
                FROM user_devices
                WHERE user_id = $1
                ORDER BY last_active DESC
                `,
                [req.auth.userId]
            );

            return res.json({
                user: userResult.rows[0],
                devices: devicesResult.rows,
                cloudPublicKey: getCloudPublicKey(),
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
                    error: "refreshToken là bắt buộc",
                });
            }

            let decoded;

            try {
                decoded = verifyRefreshToken(refreshToken);
            } catch (err) {
                return res.status(401).json({
                    error: "Refresh token không hợp lệ hoặc đã hết hạn",
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
                    error: "User not found",
                });
            }

            const user = userResult.rows[0];

            const newAccessToken = signAccessToken(user);

            return res.json({
                message: "Cấp lại access token thành công",
                accessToken: newAccessToken,
                user,
                cloudPublicKey: getCloudPublicKey(),
            });
        } catch (err) {
            return res.status(500).json({
                error: err.message,
            });
        }
    },
};