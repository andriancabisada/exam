const express = require("express");
const bodyParser = require("body-parser");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const Holidays = require("date-holidays");

const app = express();
const port = process.env.PORT || 3000;

// Set up PostgreSQL pool
const pool = new Pool({
  connectionString:
    process.env.DATABASE_URL || "postgres://localhost:5432/holidays",
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// Set up JSON parsing middleware
app.use(bodyParser.json());

// function for checking jwt auth
function verifyAuthToken(authToken) {
  try {
    const token = authToken.split(" ")[1];
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    return decodedToken.id;
  } catch {
    return null;
  }
}

// Endpoint to retrieve paginated list of holidays for a country
app.get("/holidays/:country_code", async (req, res) => {
  const { country_code } = req.params;
  const hd = new Holidays(country_code);

  // Get holidays for current year
  const year = new Date().getFullYear();
  const holidays = hd.getHolidays(year);

  // Paginate holidays
  const limit = req.query.limit || 10;
  const offset = req.query.offset || 0;
  const paginatedHolidays = holidays.slice(offset, offset + limit);

  res.json(paginatedHolidays);
});

// Endpoint to retrieve holiday by code for a country
app.get("/holidays/:country_code/:holiday_code", async (req, res) => {
  const { country_code, holiday_code } = req.params;
  const hd = new Holidays(country_code);
  const holiday = hd.getHoliday(holiday_code);

  if (!holiday) {
    res.status(404).json({ error: "Holiday not found" });
    return;
  }

  res.json(holiday);
});

// Endpoint to create a new user account
app.post("/sign-up", async (req, res) => {
  const { username, password, role } = req.body;

  // Check if user already exists
  const result = await pool.query("SELECT * FROM users WHERE username = $1", [
    username,
  ]);
  if (result.rows.length > 0) {
    res.status(400).json({ error: "User already exists" });
    return;
  }

  // Insert user into database

  const query =
    "INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id";
  const values = [username, password, role];
  const { id } = (await pool.query(query, values)).rows[0];

  res.json({ id, username, role });
});

// Endpoint to save a holiday to a user's account
app.post("/save-holiday/:holiday_id", async (req, res) => {
  const { holiday_id } = req.params;
  const { authorization } = req.headers;

  // Verify user is authenticated
  const userId = verifyAuthToken(authorization);
  if (!userId) {
    res.status(401).json({ error: "Not authorized" });
    return;
  }

  // Check if holiday is already saved
  const result = await pool.query(
    "SELECT * FROM user_holidays WHERE user_id = $1 AND holiday_id = $2",
    [userId, holiday_id]
  );
  if (result.rows.length > 0) {
    res.status(200).json({ message: "Holiday already saved" });
    return;
  }

  // Save holiday to user's account
  const query =
    "INSERT INTO user_holidays (user_id, holiday_id) VALUES ($1, $2)";
  const values = [userId, holiday_id];
  await pool.query(query, values);

  res.json({ message: "Holiday saved" });
});

// Endpoint to delete a holiday from a user's account
app.delete("/unsave-holiday/:holiday_id", async (req, res) => {
  const { holiday_id } = req.params;
  const { authorization } = req.headers;

  // Verify user is authenticated
  const userId = verifyAuthToken(authorization);
  if (!userId) {
    res.status(401).json({ error: "Not authorized" });
    return;
  }

  // Delete saved holiday from user's account
  const query =
    "DELETE FROM user_holidays WHERE user_id = $1 AND holiday_id = $2";
  const values = [userId, holiday_id];
  const result = await pool.query(query, values);

  if (result.rowCount === 0) {
    res.status(200).json({ message: "Holiday not found" });
    return;
  }

  res.json({ message: "Holiday deleted" });
});

const bcrypt = require("bcryptjs");

// Endpoint to log in and return JWT token
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // Check if email exists
  const result = await pool.query("SELECT * FROM users WHERE email = $1", [
    email,
  ]);
  if (result.rows.length === 0) {
    res.status(401).json({ error: "Invalid email or password" });
    return;
  }

  // Check password
  const user = result.rows[0];
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    res.status(401).json({ error: "Invalid email or password" });
    return;
  }

  // Create and return JWT token
  const token = jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
  res.json({ token });
});
