require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

pool.connect()
  .then(() => {
    console.log("Database Connected ✅");
  })
  .catch(err => {
    console.error("Database connection error:", err);
  });

    return pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100),
        email VARCHAR(100) UNIQUE,
        password VARCHAR(200),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
  })
  .then(() => console.log("Users table ready ✅"))
  .catch(err => console.error("DB Error ❌", err));

app.get("/", (req, res) => {
  res.send("Netflix Backend Running 🚀");
});
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
      [name, email, hashedPassword]
    );

    res.json({
      message: "User created successfully ✅",
      user: result.rows[0]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Something went wrong ❌" });
  }
});
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (user.rows.length === 0) {
      return res.status(400).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(
      password,
      user.rows[0].password
    );

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid password" });
    }

    res.json({ message: "Login successful ✅" });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});
// 🔐 JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json({ message: "Access Denied ❌ No token" });
  }

  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Token missing ❌" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token ❌" });
    }

    req.user = user;
    next();
  });
};
// 🔐 Protected Dashboard Route
app.get("/dashboard", authenticateToken, (req, res) => {
  res.json({
    message: "Welcome to your dashboard 🎉",
    userid: req.user.id
  });
});


// 👇 PASTE LOGIN ROUTE HERE
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (user.rows.length === 0) {
      return res.status(400).json({ message: "User not found" });
    }

    if (user.rows[0].password !== password) {
      return res.status(400).json({ message: "Invalid password" });
    }

    res.json({ message: "Login successful" });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});


// DO NOT TOUCH THIS
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
