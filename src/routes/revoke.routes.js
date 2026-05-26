const express = require("express");
const router = express.Router();
 
const revokeController = require("../controllers/revoke.controller");
const { verifyToken, requireRole } = require("../middleware/auth.middleware");
 
// CASE 1.1 - Owner thu hồi Friend
// Cloud chuyển Friend key sang REVOKED ngay và tạo revoke job PENDING
// để app đồng bộ INS_REMOVE_FRIEND xuống xe / soft-wipe ở Friend app.
router.post(
    "/friend",
    verifyToken,
    requireRole("USER"),
    revokeController.createFriendRevokeRequest
);
 
// Lấy các revoke job đang chờ xử lý.
// Owner thấy job do mình tạo; Friend thấy job cần soft-wipe local key.
router.get(
    "/jobs",
    verifyToken,
    requireRole("USER"),
    revokeController.listMyRevokeJobs
);
 
// Báo cáo job đã đồng bộ với xe hoặc Friend app đã wipe local key.
router.post(
    "/jobs/report",
    verifyToken,
    requireRole("USER"),
    revokeController.reportRevokeJob
);
 
// Backward compatible với route cũ /revoke/report.
router.post(
    "/report",
    verifyToken,
    requireRole("USER"),
    revokeController.reportRevokeJob
);
 
// CASE 1.2 - Owner tự thu hồi khóa gốc / reset xe.
// Chỉ gọi sau khi app đã chạy CMD_REVOKE_OWNER bằng Standard Transaction
// và xe xác nhận đã xóa NVS thành công.
router.post(
    "/owner",
    verifyToken,
    requireRole("USER"),
    revokeController.revokeOwnerKey
);
 
// CASE 2 - Cloud/Admin chủ động tạo yêu cầu thu hồi Owner từ xa.
// Bước này chưa cho Owner app wipe; phải đợi xe trả Revocation Attestation.
router.post(
    "/owner/cloud-request",
    verifyToken,
    requireRole("ADMIN"),
    revokeController.createCloudOwnerRevokeRequest
);
 
 
// Lấy Cloud Dilithium3 public key để cấu hình/pin trên Vehicle hoặc simulator.
// Public key không phải bí mật, nhưng route vẫn giới hạn ADMIN để tránh lộ chi tiết triển khai.
router.get(
    "/owner/cloud-public-key",
    verifyToken,
    requireRole("ADMIN"),
    revokeController.getCloudRevokeSigningPublicKey
);
 
// Debug/test only: kiểm tra signedPayload + signature có hợp lệ không.
// Vehicle thật nên tự verify bằng public key đã pin, không phụ thuộc API này.
router.post(
    "/owner/cloud-command/verify",
    verifyToken,
    requireRole("ADMIN"),
    revokeController.verifyCloudSignedRevokeCommand
);
 
// CASE 2 - Hoàn tất thu hồi Owner bằng Revocation Attestation do xe ký.
// Sau khi nhận attestation, Cloud xóa key, set xe UNPAIRED và trả payload để push cho Owner app verify & wipe.
router.post(
    "/owner/cloud-attestation",
    verifyToken,
    requireRole("ADMIN"),
    revokeController.completeCloudOwnerRevokeWithAttestation
);
 
module.exports = router;
