// src/routes/revoke.routes.js

const express = require("express");
const router = express.Router();

const revokeController = require("../controllers/revoke.controller");
const authMiddlewareModule = require("../middleware/auth.middleware");

/**
 * Fix lỗi:
 * TypeError: argument handler must be a function
 *
 * Vì mỗi project có thể export middleware khác nhau:
 * - module.exports = authMiddleware
 * - exports.authMiddleware = ...
 * - exports.verifyToken = ...
 * - exports.authenticateToken = ...
 */
const authMiddleware =
    typeof authMiddlewareModule === "function"
        ? authMiddlewareModule
        : authMiddlewareModule.authMiddleware ||
          authMiddlewareModule.verifyToken ||
          authMiddlewareModule.authenticateToken ||
          authMiddlewareModule.verifyAccessToken ||
          authMiddlewareModule.protect ||
          authMiddlewareModule.requireAuth;

if (typeof authMiddleware !== "function") {
    throw new Error(
        "auth.middleware.js không export function hợp lệ. Hãy kiểm tra tên export của auth middleware."
    );
}

/**
 * Debug nhẹ để nếu còn lỗi thì biết controller đang export gì.
 * Có thể xóa sau khi chạy ổn.
 */
console.log("revokeController keys:", Object.keys(revokeController));

/**
 * Public / debug endpoints
 * Không cần login.
 */

// Lấy Cloud public key để xe/app verify chữ ký revoke từ Cloud
router.get(
    "/cloud/public-key",
    revokeController.getCloudRevokeSigningPublicKey
);

// Verify signed revoke command từ Cloud
router.post(
    "/cloud/verify",
    revokeController.verifyCloudSignedRevokeCommand
);

/**
 * Authenticated user endpoints
 * Cần access token.
 */

// CASE 1.1 - Owner thu hồi Friend
router.post(
    "/friend",
    authMiddleware,
    revokeController.createFriendRevokeRequest
);

// Lấy danh sách revoke jobs của user hiện tại
router.get(
    "/jobs",
    authMiddleware,
    revokeController.listMyRevokeJobs
);

// Báo cáo hoàn tất/thất bại revoke job
router.post(
    "/jobs/report",
    authMiddleware,
    revokeController.reportRevokeJob
);

// CASE 1.2 - Owner tự thu hồi/reset xe
router.post(
    "/owner",
    authMiddleware,
    revokeController.revokeOwnerKey
);

// CASE 2 - Cloud chủ động thu hồi Owner
router.post(
    "/cloud/owner",
    authMiddleware,
    revokeController.createCloudOwnerRevokeRequest
);

/**
 * Vehicle / simulator endpoint
 * Xe gửi kết quả revoke về Cloud.
 * Hiện để public để ESP32/simulator gọi được.
 * Nếu sau này có token riêng cho ESP32 thì thêm middleware ở đây.
 */
router.post(
    "/cloud/owner/vehicle-result",
    revokeController.completeCloudOwnerRevokeWithVehicleResult
);

module.exports = router;