const express = require("express");
const router = express.Router();

const vehicleController = require("../controllers/vehicle.controller");
const authMiddlewareModule = require("../middleware/auth.middleware");

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
    throw new Error("auth.middleware.js không export function hợp lệ.");
}

router.post(
    "/register",
    authMiddleware,
    vehicleController.registerVehicle
);

router.post(
    "/register-identity",
    vehicleController.registerVehicleIdentity
);

router.get(
    "/my-modules",
    authMiddleware,
    vehicleController.getMyModules
);

router.get(
    "/:moduleId/status",
    vehicleController.getVehicleStatusForDevice
);

router.get(
    "/:moduleId",
    authMiddleware,
    vehicleController.getVehicleDetail
);

module.exports = router;