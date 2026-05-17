const debugEvents = [];

function maskSensitiveData(data) {
    if (!data || typeof data !== "object") return data;

    const masked = Array.isArray(data) ? [...data] : { ...data };

    const sensitiveKeys = [
        "password",
        "pass",
        "accessToken",
        "refreshToken",
        "token",
        "authorization",
        "signature"
    ];

    for (const key of Object.keys(masked)) {
        const lowerKey = key.toLowerCase();

        if (sensitiveKeys.some(sensitive => lowerKey.includes(sensitive.toLowerCase()))) {
            masked[key] = "***MASKED***";
        } else if (typeof masked[key] === "object" && masked[key] !== null) {
            masked[key] = maskSensitiveData(masked[key]);
        }
    }

    return masked;
}

function addDebugEvent(event) {
    debugEvents.unshift({
        id: Date.now() + "-" + Math.random().toString(16).slice(2),
        time: new Date().toLocaleString("vi-VN"),
        ...event
    });

    if (debugEvents.length > 100) {
        debugEvents.pop();
    }
}

function requestLogger(req, res, next) {
    if (req.originalUrl.startsWith("/debug")) {
        return next();
    }

    const startTime = Date.now();

    const originalJson = res.json.bind(res);

    res.json = function (body) {
        const durationMs = Date.now() - startTime;

        addDebugEvent({
            method: req.method,
            url: req.originalUrl,
            statusCode: res.statusCode,
            durationMs,
            request: {
                headers: {
                    authorization: req.headers.authorization ? "Bearer ***MASKED***" : null,
                    contentType: req.headers["content-type"] || null,
                    userAgent: req.headers["user-agent"] || null
                },
                body: maskSensitiveData(req.body),
                query: req.query
            },
            response: maskSensitiveData(body)
        });

        return originalJson(body);
    };

    next();
}

function getDebugEvents(req, res) {
    return res.json({
        events: debugEvents
    });
}

function clearDebugEvents(req, res) {
    debugEvents.length = 0;

    return res.json({
        message: "Đã xóa debug events"
    });
}

module.exports = {
    requestLogger,
    getDebugEvents,
    clearDebugEvents
};