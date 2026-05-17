const express = require("express");
const router = express.Router();

const revokeController = require("../controllers/revoke.controller");
const { verifyToken, requireRole } = require("../middleware/auth.middleware");

// Owner gửi yêu cầu thu hồi key của Friend
// Chỉ tạo revoke_jobs.status = PENDING, chưa xóa digital_keys
router.post(
    "/friend",
    verifyToken,
    requireRole("USER"),
    revokeController.createFriendRevokeRequest
);

// Friend xem các yêu cầu revoke đang chờ mình xử lý
router.get(
    "/jobs",
    verifyToken,
    requireRole("USER"),
    revokeController.listMyRevokeJobs
);

// Friend xác nhận đã chấp nhận/xóa key local
// Lúc này server mới xóa Friend key khỏi digital_keys
router.post(
    "/report",
    verifyToken,
    requireRole("USER"),
    revokeController.reportRevokeJob
);

// Owner tự thu hồi khóa gốc
router.post(
    "/owner",
    verifyToken,
    requireRole("USER"),
    revokeController.revokeOwnerKey
);

module.exports = router;