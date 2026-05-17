const express = require("express");
const router = express.Router();

const vehicleController = require("../controllers/vehicle.controller");
const { verifyToken, requireRole } = require("../middleware/auth.middleware");

router.post(
    "/register",
    verifyToken,
    requireRole("USER"),
    vehicleController.registerVehicle
);

router.get(
    "/my-modules",
    verifyToken,
    requireRole("USER"),
    vehicleController.getMyModules
);

router.get(
    "/:moduleId",
    verifyToken,
    requireRole("USER"),
    vehicleController.getVehicleDetail
);

module.exports = router;