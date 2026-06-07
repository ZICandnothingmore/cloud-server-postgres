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
            const normalizedIdentityPk = identity_pk ? normalizeIdentityPk(identity_pk) : null;
    
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
                INSERT INTO users (
                    email,
                    password_hash,
                    display_name,
                    role,
                    identity_pk
                )
                VALUES ($1, $2, $3, 'USER', $4)
                RETURNING
                    id,
                    email,
                    display_name,
                    role,
                    identity_pk,
                    created_at
                `,
                [
                    normalizedEmail,
                    passwordHash,
                    finalDisplayName,
                    normalizedIdentityPk,
                ]
            );
    
            const user = userResult.rows[0];
    
            let device = null;
    
            if (deviceName || fcmToken) {
                const deviceResult = await client.query(
                    `
                    INSERT INTO user_devices (
                        user_id,
                        device_name,
                        fcm_token,
                        last_active
                    )
                    VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
                    RETURNING
                        id,
                        user_id,
                        device_name,
                        fcm_token,
                        last_active,
                        created_at
                    `,
                    [
                        user.id,
                        deviceName || null,
                        fcmToken || null,
                    ]
                );
    
                device = deviceResult.rows[0];
            }
    
            await client.query("COMMIT");
    
            const safeUser = sanitizeUser(user);
    
            const accessToken = signAccessToken(safeUser);
            const refreshToken = signRefreshToken(safeUser);
    
            return res.status(201).json({
                message: "Tạo tài khoản thành công",
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
                detail: err.detail,
                hint: err.hint,
                code: err.code,
            });
        } finally {
            client.release();
        }
    },

    login: async (req, res) => {
        const client = await pool.connect();
    
        try {
            let {
                email,
                password,
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
            
            const isAdminLogin =
                normalizedEmail === "admin@gmail.com" ||
                normalizedEmail === "admin1@gmail.com";
            
            if (!isAdminLogin && !identity_pk) {
                return res.status(400).json({
                    error: "identity_pk là bắt buộc",
                });
            }
            
            const normalizedIdentityPk = identity_pk
                ? normalizeIdentityPk(identity_pk)
                : null;
            
            await client.query("BEGIN");
    
            const userResult = await client.query(
                `
                SELECT
                    id,
                    email,
                    password_hash,
                    display_name,
                    role,
                    identity_pk,
                    created_at
                FROM public.users
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
    
            let user = userResult.rows[0];
    
            const isMatch = await comparePassword(password, user.password_hash);
    
            if (!isMatch) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    error: "Email hoặc mật khẩu không đúng",
                });
            }
    
            /**
             * identity_pk bây giờ thuộc về USER.
             * Nếu user chưa có identity_pk thì cập nhật lần đầu.
             * Nếu đã có rồi thì bắt buộc phải khớp.
             */
            if (!user.identity_pk) {
                const updatedUserResult = await client.query(
                    `
                    UPDATE users
                    SET identity_pk = $1
                    WHERE id = $2
                    RETURNING
                        id,
                        email,
                        password_hash,
                        display_name,
                        role,
                        identity_pk,
                        created_at
                    `,
                    [normalizedIdentityPk, user.id]
                );
    
                user = updatedUserResult.rows[0];
            } else if (user.identity_pk !== normalizedIdentityPk) {
                await client.query("ROLLBACK");
                return res.status(403).json({
                    error: "Identity public key không khớp với tài khoản",
                    detail: "identity_pk gửi lên không trùng với identity_pk của user",
                });
            }
    
            /**
             * user_devices bây giờ chỉ lưu thông tin thiết bị đăng nhập.
             * KHÔNG kiểm tra identity_pk ở bảng user_devices nữa.
             *
             * Nếu có fcmToken thì dùng fcmToken để nhận biết cùng 1 app/device.
             * Nếu chưa có thì tạo bản ghi mới.
             */
            let deviceResult;
    
            if (fcmToken) {
                deviceResult = await client.query(
                    `
                    SELECT
                        id,
                        user_id,
                        device_name,
                        fcm_token,
                        last_active,
                        created_at
                    FROM public.user_devices
                    WHERE user_id = $1
                      AND fcm_token = $2
                    LIMIT 1
                    `,
                    [user.id, fcmToken]
                );
            } else {
                deviceResult = await client.query(
                    `
                    SELECT
                        id,
                        user_id,
                        device_name,
                        fcm_token,
                        last_active,
                        created_at
                    FROM public.user_devices
                    WHERE user_id = $1
                      AND device_name = $2
                    LIMIT 1
                    `,
                    [user.id, deviceName || null]
                );
            }
    
            let device = null;
    
            if (deviceResult.rows.length > 0) {
                const updatedDeviceResult = await client.query(
                    `
                    UPDATE user_devices
                    SET device_name = COALESCE($1, device_name),
                        fcm_token = COALESCE($2, fcm_token),
                        last_active = CURRENT_TIMESTAMP
                    WHERE id = $3
                    RETURNING
                        id,
                        user_id,
                        device_name,
                        fcm_token,
                        last_active,
                        created_at
                    `,
                    [
                        deviceName || null,
                        fcmToken || null,
                        deviceResult.rows[0].id,
                    ]
                );
    
                device = updatedDeviceResult.rows[0];
            } else {
                const createdDeviceResult = await client.query(
                    `
                    INSERT INTO user_devices (
                        user_id,
                        device_name,
                        fcm_token,
                        last_active
                    )
                    VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
                    RETURNING
                        id,
                        user_id,
                        device_name,
                        fcm_token,
                        last_active,
                        created_at
                    `,
                    [
                        user.id,
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
                SELECT
                    id,
                    email,
                    display_name,
                    role,
                    identity_pk,
                    created_at,
                    updated_at
                FROM public.users
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
                    device_name,
                    fcm_token,
                    last_active,
                    created_at
                FROM public.user_devices
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
                detail: err.detail,
                hint: err.hint,
                code: err.code,
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
                FROM public.users
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