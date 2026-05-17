require("dotenv").config();

const express = require("express");
const cors = require("cors");

const pool = require("./config/db");

const app = express();

app.use(cors());
app.use(express.json());
const sharingRoutes = require("./routes/sharing.routes");
const {
    requestLogger,
    getDebugEvents,
    clearDebugEvents
} = require("./utils/requestLogger");

app.use(requestLogger);

app.use(express.static("public"));

app.get("/health", async (req, res) => {
    try {
        const result = await pool.query("SELECT NOW()");
        res.json({
            status: "ok",
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


app.get("/debug/events", getDebugEvents);
app.delete("/debug/events", clearDebugEvents);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server running at port ${PORT}`);
});