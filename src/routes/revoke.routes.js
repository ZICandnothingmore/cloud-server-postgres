const express = require("express");
const router = express.Router();
 
const revokeController = require("../controllers/revoke.controller");
const authMiddlewareModule = require("../middleware/auth.middleware");
 
const authMiddleware =
    typeof authMiddlewareModule === "function"
        ? authMiddlewareModule
        : authMiddlewareModule.authMiddleware ||
          authMiddlewareModule.verifyToken ||
          authMiddlewareModule.authenticateToken ||
          authMiddlewareModule.verifyAccessToken ||
          authMiddlewareModule.requireAuth;
 
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
 
// Lấy danh sách revoke jobs PENDING của user hiện tại
// Owner sẽ nhận OWNER_VEHICLE_SYNC; Friend sẽ nhận FRIEND_LOCAL_WIPE.
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
 
/**
 * CASE 2 - Cloud/Admin thu hồi Owner từ xa theo status-based flow.
 * Admin tạo yêu cầu revoke.
 * Server set vehicles.status = REVOKE_PENDING.
 */
 
// API cũ: moduleID truyền trong body
router.post(
    "/owner/cloud-request",
    authMiddleware,
    revokeController.createCloudOwnerRevokeRequest
);
 
// API mới/gọn: moduleId truyền trên URL
router.post(
    "/owner/cloud-request/:moduleId",
    authMiddleware,
    revokeController.createCloudOwnerRevokeRequestByModuleId
);
 
/**
 * ESP32 báo kết quả revoke về Server.
 * ESP32 chỉ gửi SUCCESS/FAILED.
 */
router.post(
    "/owner/cloud-request/:moduleId/result",
    revokeController.completeCloudOwnerRevokeWithVehicleResult
);
 
module.exports = router;
