const { verifyAccessToken } = require("../utils/jwt");

function verifyToken(req, res, next) {
    const header = req.headers.authorization;

    if (!header || !header.startsWith("Bearer ")) {
        return res.status(401).json({
            error: "No token provided",
        });
    }

    const token = header.split(" ")[1];

    try {
        const decoded = verifyAccessToken(token);
        req.auth = decoded;
        next();
    } catch (err) {
        return res.status(401).json({
            error: "Invalid token",
        });
    }
}

function requireRole(...allowedRoles) {
    return function (req, res, next) {
        if (!req.auth) {
            return res.status(401).json({
                error: "Unauthenticated",
            });
        }

        if (!allowedRoles.includes(req.auth.role)) {
            return res.status(403).json({
                error: "Permission denied",
            });
        }

        next();
    };
}

module.exports = {
    verifyToken,
    requireRole,
};