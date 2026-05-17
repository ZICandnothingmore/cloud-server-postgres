const express = require("express");
const router = express.Router();

const sharingController = require("../controllers/sharing.controller");
const { verifyToken, requireRole } = require("../middleware/auth.middleware");

router.post(
    "/check-legality",
    verifyToken,
    requireRole("USER"),
    sharingController.checkLegality
);

router.post(
    "/check",
    verifyToken,
    requireRole("USER"),
    sharingController.checkLegality
);

router.post(
    "/invite",
    verifyToken,
    requireRole("USER"),
    sharingController.invite
);

router.get(
    "/pending",
    verifyToken,
    requireRole("USER"),
    sharingController.pending
);

router.post(
    "/claim",
    verifyToken,
    requireRole("USER"),
    sharingController.claim
);

router.post(
    "/report",
    verifyToken,
    requireRole("USER"),
    sharingController.report
);

router.post(
    "/report-outcome",
    verifyToken,
    requireRole("USER"),
    sharingController.report
);

module.exports = router;