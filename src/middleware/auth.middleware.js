const jwt = require("jsonwebtoken");
const pool = require("../config/db");

function extractBearerToken(req) {
    const authHeader = req.headers.authorization || req.headers.Authorization;

    if (!authHeader) return null;

    const parts = authHeader.split(" ");

    if (parts.length !== 2 || parts[0] !== "Bearer") {
        return null;
    }

    return parts[1];
}

async function verifyToken(req, res, next) {
    try {
        const token = extractBearerToken(req);

        if (!token) {
            return res.status(401).json({
                error: "Missing or invalid Authorization header"
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const userId =
            decoded.userId ||
            decoded.user_id ||
            decoded.id ||
            decoded.sub;

        if (!userId) {
            return res.status(401).json({
                error: "Invalid token payload: missing user id"
            });
        }

        /**
         * QUAN TRỌNG:
         * Không tin role trong JWT cũ nữa.
         * Mỗi request đọc role mới nhất từ database.
         */
        const userResult = await pool.query(
            `
            SELECT id, email, role
            FROM users
            WHERE id = $1::uuid
            LIMIT 1
            `,
            [userId]
        );

        if (userResult.rows.length === 0) {
            return res.status(401).json({
                error: "User not found"
            });
        }

        const user = userResult.rows[0];

        req.auth = {
            ...decoded,
            userId: user.id,
            user_id: user.id,
            email: user.email,
            role: String(user.role || "").trim().toUpperCase()
        };

        req.user = req.auth;

        return next();
    } catch (err) {
        return res.status(401).json({
            error: "Invalid or expired token",
            detail: err.message
        });
    }
}

function requireRole(...allowedRoles) {
    return (req, res, next) => {
        const currentRole = String(req.auth?.role || req.user?.role || "")
            .trim()
            .toUpperCase();

        const normalizedAllowedRoles = allowedRoles
            .flat()
            .map(role => String(role).trim().toUpperCase());

        if (!currentRole) {
            return res.status(403).json({
                error: "Permission denied",
                detail: "Missing role in authenticated user",
                expectedRoles: normalizedAllowedRoles
            });
        }

        if (!normalizedAllowedRoles.includes(currentRole)) {
            return res.status(403).json({
                error: "Permission denied",
                detail: `Current role '${currentRole}' is not allowed`,
                currentRole,
                expectedRoles: normalizedAllowedRoles
            });
        }

        return next();
    };
}

module.exports = {
    verifyToken,
    requireRole
};