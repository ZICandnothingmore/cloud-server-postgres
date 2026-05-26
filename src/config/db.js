// const { Pool } = require("pg");
// require("dotenv").config();

// const pool = new Pool({
//     host: process.env.DB_HOST || "localhost",
//     port: Number(process.env.DB_PORT || 5432),
//     database: process.env.DB_NAME,
//     user: process.env.DB_USER,
//     password: process.env.DB_PASSWORD,
// });

// pool.on("connect", () => {
//     console.log("PostgreSQL connected");
// });

// pool.on("error", (err) => {
//     console.error("PostgreSQL error:", err.message);
// });

const { Pool } = require("pg");
require("dotenv").config();

const isProduction = process.env.NODE_ENV === "production";

const pool = new Pool(
  process.env.DB_URL
    ? {
        connectionString: process.env.DB_URL,
        ssl: isProduction
          ? {
              rejectUnauthorized: false,
            }
          : false,
      }
    : {
        host: process.env.DB_HOST || "localhost",
        port: Number(process.env.DB_PORT || 5432),
        database: process.env.DB_NAME,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
      }
);

pool.on("connect", () => {
  console.log("PostgreSQL connected");
});

pool.on("error", (err) => {
  console.error("PostgreSQL error:", err.message);
});

module.exports = pool;

// module.exports = pool;

// const { Pool } = require("pg");
// require("dotenv").config();

// const pool = new Pool(
//   process.env.DB_URL
//     ? {
//         connectionString: process.env.DB_URL,
//         ssl: {
//           rejectUnauthorized: false,
//         },
//       }
//     : {
//         host: process.env.DB_HOST || "localhost",
//         port: Number(process.env.DB_PORT || 5432),
//         database: process.env.DB_NAME,
//         user: process.env.DB_USER,
//         password: process.env.DB_PASSWORD,
//       }
// );

// pool.on("connect", () => {
//   console.log("PostgreSQL connected");
// });

// pool.on("error", (err) => {
//   console.error("PostgreSQL error:", err.message);
// });

// module.exports = pool;