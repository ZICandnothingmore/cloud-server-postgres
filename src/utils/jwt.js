const jwt = require("jsonwebtoken");

function signAccessToken(user) {
    return jwt.sign(
        {
            userId: user.id,
            email: user.email,
            role: user.role || "USER"
        },
        process.env.JWT_ACCESS_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRES || "1h",
        }
    );
}

function signRefreshToken(user) {
    return jwt.sign(
        {
            userId: user.id,
            email: user.email,
            role: user.role || "USER"
        },
        process.env.JWT_REFRESH_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRES || "30d",
        }
    );
}

function verifyAccessToken(token) {
    return jwt.verify(token, process.env.JWT_ACCESS_SECRET);
}

function verifyRefreshToken(token) {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
}

module.exports = {
    signAccessToken,
    signRefreshToken,
    verifyAccessToken,
    verifyRefreshToken,
};