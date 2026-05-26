const { Pool } = require("pg");
require("dotenv").config();

const pool = new Pool({
    host: process.env.DB_HOST || "localhost",
    port: Number(process.env.DB_PORT || 5432),
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
});

pool.on("connect", () => {
    console.log("PostgreSQL connected");
});

pool.on("error", (err) => {
    console.error("PostgreSQL error:", err.message);
});

module.exports = pool;

// require("dotenv").config();

// const { Pool } = require("pg");

// const hasLocalConfig = Boolean(process.env.DB_HOST || process.env.DB_NAME || process.env.DB_USER);

// const poolConfig = hasLocalConfig
//     ? {
//         host: process.env.DB_HOST || "localhost",
//         port: Number(process.env.DB_PORT || 5432),
//         database: process.env.DB_NAME,
//         user: process.env.DB_USER,
//         password: process.env.DB_PASSWORD,
//     }
//     : {
//         connectionString: process.env.DB_URL,
//         ssl: {
//             rejectUnauthorized: false,
//         },
//     };

// const pool = new Pool(poolConfig);

// module.exports = pool;
