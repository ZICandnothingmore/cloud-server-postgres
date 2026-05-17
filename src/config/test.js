require("dotenv").config({
  path: "../../.env"
});

const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DB_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

async function test() {
  const result = await pool.query("SELECT NOW()");
  console.log(result.rows);
}

test();