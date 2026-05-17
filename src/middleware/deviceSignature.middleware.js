const pool = require("../config/db");

async function verifyDeviceSignature(req, res, next) {
    try {
        const { signature } = req.body;

        if (!signature) {
            return res.status(403).json({
                error: "Thiếu chữ ký điện tử"
            });
        }

        const deviceResult = await pool.query(
            `
            SELECT id, user_id, identity_pk, device_name
            FROM user_devices
            WHERE user_id = $1
            ORDER BY last_active DESC
            `,
            [req.auth.userId]
        );

        if (deviceResult.rows.length === 0) {
            return res.status(403).json({
                error: "Không tìm thấy thiết bị định danh của tài khoản hiện tại"
            });
        }

        req.authDevices = deviceResult.rows;

        if (process.env.MOCK_SIGNATURE === "true") {
            req.signatureVerified = true;
            return next();
        }

        /*
         * TODO verify Dilithium signature thật.
         *
         * Hiện app gửi:
         * - keyId
         * - signature
         *
         * Backend cần thống nhất chính xác với app:
         * - app ký lên dữ liệu gì? Ví dụ: keyId hay "REVOKE:" + keyId
         * - identity_pk là public key Dilithium dạng hex đúng không?
         * - signature là hex của chữ ký Dilithium đúng không?
         *
         * Sau khi thống nhất, backend sẽ dùng identity_pk trong user_devices
         * để verify signature.
         */

        return res.status(501).json({
            error: "Real Dilithium signature verification chưa được cấu hình"
        });
    } catch (err) {
        return res.status(500).json({
            error: err.message
        });
    }
}

module.exports = verifyDeviceSignature;