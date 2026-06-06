const express = require("express");

const router = express.Router();

const authController = require("../controllers/auth.controller");
const { verifyToken, requireRole } = require("../middleware/auth.middleware");

router.post(
    "/register",
    verifyToken,
    requireRole("ADMIN"),
    authController.register
);

router.post("/login", authController.login);

router.patch("/fcm-token", verifyToken, authController.updateFcmToken);
router.get("/me", verifyToken, authController.me);
router.post("/refresh", authController.refreshToken);

function getDisplayName(displayName, email) {
  const cleanedDisplayName = String(displayName || "").trim();

  if (cleanedDisplayName) {
      return cleanedDisplayName;
  }

  return String(email || "")
      .trim()
      .split("@")[0];
}

module.exports = router;