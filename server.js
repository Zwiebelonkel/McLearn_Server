import "dotenv/config";
import express from "express";
import cors from "cors";
import { nanoid } from "nanoid";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import db from './db.js';
import { verifyToken, requireAuth } from "./auth.js";

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret';

// CORS für alle Origins erlauben
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization", "X-API-Key"],
  })
);

app.use(express.json());

/* ------------------ LOGIN / REGISTER ------------------ */
app.post("/api/login", async (req, res) => {
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
      { expiresIn: "8h" }
    );

    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ message: "Login-Fehler" });
  }
});

app.post("/api/register", async (req, res) => {
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

/* ------------------ HEALTH ------------------ */
app.get("/api/health", (_req, res) => res.json({ ok: true }));

/* ------------------ STACKS ------------------ */

// Alle öffentlichen Stacks
app.get("/api/stacks/public", async (_req, res) => {
  const { rows } = await db.execute(
    `SELECT * FROM stacks WHERE is_public = true ORDER BY created_at DESC`
  );
  res.json(rows);
});

// Nur eigene Stacks
app.get("/api/stacks/mine", requireAuth, async (req, res) => {
  const userId = req.user.id;
  const { rows } = await db.execute(
    `SELECT * FROM stacks WHERE user_id=? ORDER BY created_at DESC`,
    [userId]
  );
  res.json(rows);
});

// Kombiniert: eigene + öffentliche
app.post("/api/stacks", async (req, res) => {
  const { name, public: isPublic } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: "name required" });
  const id = nanoid();
  const now = new Date().toISOString();
  await db.execute({
    sql: `INSERT INTO stacks(id,name,public,created_at,updated_at) VALUES(?,?,?,?,?)`,
    args: [id, name.trim(), isPublic ? 1 : 0, now, now],
  });
  const { rows } = await db.execute({
    sql: `SELECT * FROM stacks WHERE id=?`,
    args: [id],
  });
  res.status(201).json(rows[0]);
});

// Stack erstellen
app.post("/api/stacks", requireAuth, async (req, res) => {
  const { name, is_public } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: "name required" });
  const id = nanoid();
  const now = new Date().toISOString();
  await db.execute({
    sql: `INSERT INTO stacks(id,user_id,name,is_public,created_at,updated_at) VALUES(?,?,?,?,?,?)`,
    args: [id, req.user.id, name.trim(), !!is_public, now, now],
  });
  const { rows } = await db.execute({
    sql: `SELECT * FROM stacks WHERE id=?`,
    args: [id],
  });
  res.status(201).json(rows[0]);
});

// Stack updaten
// PATCH /api/stacks/:id
app.patch("/api/stacks/:id", async (req, res) => {
  const { name, public: isPublic } = req.body || {};
  const { id } = req.params;
  if (!name?.trim()) return res.status(400).json({ error: "name required" });
  const now = new Date().toISOString();
  await db.execute({
    sql: `UPDATE stacks SET name=?, public=?, updated_at=? WHERE id=?`,
    args: [name.trim(), isPublic ? 1 : 0, now, id],
  });
  const { rows } = await db.execute({
    sql: `SELECT * FROM stacks WHERE id=?`,
    args: [id],
  });
  if (!rows.length) return res.status(404).json({ error: "not found" });
  res.json(rows[0]);
});

// Stack löschen
app.delete("/api/stacks/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  await db.execute({
    sql: `DELETE FROM stacks WHERE id=? AND user_id=?`,
    args: [id, req.user.id],
  });
  res.status(204).end();
});

/* ------------------ CARDS ------------------ */
app.get("/api/cards", requireAuth, async (req, res) => {
  const { stackId } = req.query;
  if (!stackId) return res.status(400).json({ error: "stackId required" });

  // check stack visibility
  const { rows: stacks } = await db.execute(
    "SELECT * FROM stacks WHERE id=?",
    [stackId]
  );
  const stack = stacks[0];
  if (!stack) return res.status(404).json({ error: "stack not found" });

  // only owner can see private stacks
  if (!stack.is_public && stack.user_id !== req.user.id)
    return res.status(403).json({ error: "Forbidden" });

  const { rows } = await db.execute({
    sql: `SELECT * FROM cards WHERE stack_id=? ORDER BY created_at DESC`,
    args: [stackId],
  });
  res.json(rows);
});

app.post("/api/cards", requireAuth, async (req, res) => {
  const { stack_id, front, back } = req.body || {};
  if (!stack_id || !front?.trim() || !back?.trim()) {
    return res.status(400).json({ error: "stack_id, front, back required" });
  }
  const id = nanoid();
  const now = new Date().toISOString();
  await db.execute({
    sql: `INSERT INTO cards(id,stack_id,front,back,box,due_at,created_at,updated_at)
     VALUES(?,?,?,?,1,?,?,?)`,
    args: [id, stack_id, front.trim(), back.trim(), now, now, now],
  });
  const { rows } = await db.execute({
    sql: `SELECT * FROM cards WHERE id=?`,
    args: [id],
  });
  res.status(201).json(rows[0]);
});

/* … der Rest (PATCH/DELETE Cards, Study Mode) bleibt gleich … */

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`API on :${port}`);
});
