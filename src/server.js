// require("dotenv").config();

// const express = require("express");
// const cors = require("cors");

// const pool = require("./config/db");

// const app = express();

// app.use(cors());
// app.use(express.json());
// const sharingRoutes = require("./routes/sharing.routes");
// const {
//     requestLogger,
//     getDebugEvents,
//     clearDebugEvents
// } = require("./utils/requestLogger");

// app.use(requestLogger);

// app.use(express.static("public"));

// app.get("/health", async (req, res) => {
//     try {
//         const result = await pool.query("SELECT NOW()");
//         res.json({
//             status: "ok",
//             databaseTime: result.rows[0].now,
//         });
//     } catch (err) {
//         res.status(500).json({
//             status: "error",
//             error: err.message,
//         });
//     }
// });

// const authRoutes = require("./routes/auth.routes");
// const vehicleRoutes = require("./routes/vehicle.routes");
// const syncRoutes = require("./routes/sync.routes");
// const revokeRoutes = require("./routes/revoke.routes");

// app.use("/auth", authRoutes);
// app.use("/vehicle", vehicleRoutes);
// app.use("/sharing", sharingRoutes);
// app.use("/sync", syncRoutes);
// app.use("/revoke", revokeRoutes);


// app.get("/debug/events", getDebugEvents);
// app.delete("/debug/events", clearDebugEvents);

// const PORT = process.env.PORT || 3000;

// app.listen(PORT, () => {
//     console.log(`Server running at port ${PORT}`);
// });


require("dotenv").config();

const express = require("express");
const cors = require("cors");

const pool = require("./config/db");

const app = express();

/**
 * Render đứng phía trước app và terminate HTTPS/TLS.
 * trust proxy giúp Express đọc đúng protocol/client IP qua header của proxy.
 */
app.set("trust proxy", 1);

/**
 * CORS:
 * - Local dev: cho phép localhost.
 * - Production: set CLIENT_ORIGINS trên Render, ví dụ:
 *   CLIENT_ORIGINS=https://your-frontend.onrender.com,https://your-domain.com
 *
 * Nếu ESP32/Postman gọi API thì CORS không ảnh hưởng nhiều;
 * CORS chủ yếu áp dụng cho browser/frontend.
 */
const defaultAllowedOrigins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:3001",
  
    // Render backend / frontend hiện tại
    "https://cloud-server-postgres-1.onrender.com",
  ];
  
  const envAllowedOrigins = (process.env.CLIENT_ORIGINS || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
  
  const allowedOrigins = [
    ...defaultAllowedOrigins,
    ...envAllowedOrigins,
  ];
  
  app.use(
    cors({
      origin: function (origin, callback) {
        // Cho phép request không có Origin: PowerShell, Postman, curl, ESP32...
        if (!origin) {
          return callback(null, true);
        }
  
        if (allowedOrigins.includes(origin)) {
          return callback(null, true);
        }
  
        return callback(new Error(`CORS blocked for origin: ${origin}`));
      },
      credentials: true,
    })
  );

app.use(express.json({ limit: "1mb" }));

const sharingRoutes = require("./routes/sharing.routes");
const {
    requestLogger,
    getDebugEvents,
    clearDebugEvents
} = require("./utils/requestLogger");

app.use(requestLogger);

app.use(express.static("public"));

app.get("/", (req, res) => {
    res.json({
        status: "ok",
        service: "digital-key-cloud-server",
        message: "Server is running"
    });
});

app.get("/health", async (req, res) => {
    try {
        const result = await pool.query("SELECT NOW()");
        res.json({
            status: "ok",
            env: process.env.NODE_ENV || "development",
            databaseTime: result.rows[0].now,
        });
    } catch (err) {
        res.status(500).json({
            status: "error",
            error: err.message,
        });
    }
});

const authRoutes = require("./routes/auth.routes");
const vehicleRoutes = require("./routes/vehicle.routes");
const syncRoutes = require("./routes/sync.routes");
const revokeRoutes = require("./routes/revoke.routes");

app.use("/auth", authRoutes);
app.use("/vehicle", vehicleRoutes);
app.use("/sharing", sharingRoutes);
app.use("/sync", syncRoutes);
app.use("/revoke", revokeRoutes);

/**
 * Không nên public debug endpoint trên production, trừ khi bạn bật DEBUG_EVENTS=true.
 */
if (process.env.NODE_ENV !== "production" || process.env.DEBUG_EVENTS === "true") {
    app.get("/debug/events", getDebugEvents);
    app.delete("/debug/events", clearDebugEvents);
}

/**
 * Render sẽ tự inject process.env.PORT.
 * Cần bind 0.0.0.0 để Render route traffic vào container/service được.
 */
const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on 0.0.0.0:${PORT}`);
});
