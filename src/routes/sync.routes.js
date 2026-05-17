const express = require("express");
const router = express.Router();

const syncController = require("../controllers/sync.controller");
const { verifyToken, requireRole } = require("../middleware/auth.middleware");

router.post(
    "/upload",
    verifyToken,
    requireRole("USER"),
    syncController.uploadKey
);

router.post(
    "/upload-key",
    verifyToken,
    requireRole("USER"),
    syncController.uploadKey
);

router.get(
    "/list",
    verifyToken,
    requireRole("USER"),
    syncController.listKeys
);

module.exports = router;