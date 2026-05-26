const express = require("express");
const router = express.Router();
const pool = require("../config/db");

const authController = require("../controllers/auth.controller");
const { verifyToken } = require("../middleware/auth.middleware");

router.post("/register", authController.register);
router.post("/login", async (req, res) => {
    console.log("========== LOGIN ROUTE HIT ==========");
    console.log("BODY:", req.body);
  
    try {
      const { email, password } = req.body;
  
      console.log("1. Email:", email);
  
      const result = await pool.query(
        "SELECT * FROM users WHERE email = $1",
        [email]
      );
  
      console.log("2. Query done, row count:", result.rowCount);
  
      const user = result.rows[0];
  
      if (!user) {
        console.log("3. User not found");
        return res.status(401).json({ error: "Invalid email or password" });
      }
  
      console.log("3. User found:", user.email);
  
      const isPasswordValid = await bcrypt.compare(password, user.password_hash);
  
      console.log("4. Password valid:", isPasswordValid);
  
      if (!isPasswordValid) {
        return res.status(401).json({ error: "Invalid email or password" });
      }
  
      console.log("5. JWT_SECRET exists:", !!process.env.JWT_SECRET);
  
      const token = jwt.sign(
        {
          userId: user.id,
          email: user.email,
          role: user.role,
        },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );
  
      console.log("6. Token created");
  
      return res.json({
        message: "Login successful",
        token,
        user,
      });
    } catch (error) {
      console.error("========== LOGIN ERROR ==========");
      console.error(error);
      console.error("Message:", error?.message);
      console.error("Stack:", error?.stack);
  
      return res.status(500).json({
        error: "Login failed",
        message: error?.message || String(error),
      });
    }
  });
router.patch("/fcm-token", verifyToken, authController.updateFcmToken);
router.get("/me", verifyToken, authController.me);
router.post("/refresh", authController.refreshToken);

module.exports = router;