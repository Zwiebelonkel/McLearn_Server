import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import db from "../db.js";

const router = Router();

router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const { rows } = await db.execute({
    sql: "SELECT * FROM users WHERE username = ?",
    args: [username],
  });

  if (!rows.length) {
    return res.status(401).json({ message: "Benutzer nicht gefunden" });
  }

  const user = rows[0];
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.status(401).json({ message: "Falsches Passwort" });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "8h" }
  );

  res.json({ success: true, token });
});

router.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  try {
    await db.execute({
      sql: "INSERT INTO users (username, password) VALUES (?, ?)",
      args: [username, hash],
    });
    res.status(201).json({ message: "Registrierung erfolgreich" });
  } catch (err) {
    res.status(409).json({ message: "Benutzername bereits vergeben" });
  }
});

export default router;
