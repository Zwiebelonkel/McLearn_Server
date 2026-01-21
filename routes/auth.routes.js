import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import db from "../db.js";
import { JWT_SECRET } from "../config/constants.js";

const router = Router();

// Login
router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await db.execute({
      sql: "SELECT * FROM users WHERE username = ?",
      args: [username],
    });
    if (result.rows.length === 0)
      return res.status(401).json({ message: "Benutzer nicht gefunden" });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: "Falsches Passwort" });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ message: "Login-Fehler" });
  }
});

// Register
router.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    await db.execute({
      sql: "INSERT INTO users (username, password) VALUES (?, ?)",
      args: [username, hash],
    });
    res.status(201).json({ message: "Registrierung erfolgreich" });
  } catch (err) {
    if (err.message.includes("UNIQUE"))
      return res.status(409).json({ message: "Benutzername bereits vergeben" });
    console.error(err);
    res.status(500).json({ message: "Fehler beim Registrieren" });
  }
});

export default router;
