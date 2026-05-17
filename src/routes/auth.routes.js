const express = require("express");
const router = express.Router();

const authController = require("../controllers/auth.controller");
const { verifyToken } = require("../middleware/auth.middleware");

router.post("/register", authController.register);
router.post("/login", authController.login);
router.patch("/fcm-token", verifyToken, authController.updateFcmToken);
router.get("/me", verifyToken, authController.me);
router.post("/refresh", authController.refreshToken);

module.exports = router;