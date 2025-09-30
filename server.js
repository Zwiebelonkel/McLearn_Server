import "dotenv/config";
import express from "express";
import cors from "cors";
import { nanoid } from "nanoid";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import db from './db.js';
import { requireAuth } from "./auth.js";

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret';

app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PATCH", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization", "X-API-Key"],
}));

app.use(express.json());

/* ========== AUTH ========== */
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

/* ========== HEALTH ========== */
app.get("/api/health", (_req, res) => res.json({ ok: true }));

/* ========== STACKS ========== */

// Alle eigenen + öffentlichen Stacks
app.get("/api/stacks", requireAuth, async (req, res) => {
  const userId = req.user.id;
  const { rows } = await db.execute({
    sql: `
      SELECT s.id, s.name, s.is_public, s.created_at, s.updated_at, s.user_id, u.username as owner_name
      FROM stacks s
      JOIN users u ON s.user_id = u.id
      WHERE s.is_public = 1 OR s.user_id = ?
      ORDER BY s.created_at DESC
    `,
    args: [userId],
  });

  res.json(rows);
});


// Stack erstellen
app.post("/api/stacks", requireAuth, async (req, res) => {
  const { name, is_public } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: "name required" });

  const id = nanoid();
  const now = new Date().toISOString();

  await db.execute({
    sql: `INSERT INTO stacks(id,user_id,name,is_public,created_at,updated_at)
          VALUES(?,?,?,?,?,?)`,
    args: [id, req.user.id, name.trim(), is_public ? 1 : 0, now, now],
  });

  const { rows } = await db.execute("SELECT s.*, u.username as owner_name FROM stacks s JOIN users u ON s.user_id = u.id WHERE s.id=?", [id]);
  res.status(201).json(rows[0]);
});

// Einzelnen Stack holen
app.get("/api/stacks/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { rows } = await db.execute("SELECT s.*, u.username as owner_name FROM stacks s JOIN users u ON s.user_id = u.id WHERE s.id=?", [id]);
  const stack = rows[0];
  if (!stack) return res.status(404).json({ error: "not found" });

  if (!stack.is_public && stack.user_id !== req.user.id)
    return res.status(403).json({ error: "Forbidden" });

  res.json(stack);
});

// Stack bearbeiten
app.patch("/api/stacks/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { name, is_public } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: "name required" });

  const now = new Date().toISOString();
  await db.execute({
    sql: `UPDATE stacks SET name=?, is_public=?, updated_at=? 
          WHERE id=? AND user_id=?`,
    args: [name.trim(), is_public ? 1 : 0, now, id, req.user.id],
  });

  const { rows } = await db.execute("SELECT s.*, u.username as owner_name FROM stacks s JOIN users u ON s.user_id = u.id WHERE s.id=?", [id]);
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

/* ========== CARDS ========== */

// Karten eines Stacks holen
app.get("/api/cards", requireAuth, async (req, res) => {
  const { stackId } = req.query;
  if (!stackId) return res.status(400).json({ error: "stackId required" });

  const { rows: stacks } = await db.execute(
    "SELECT * FROM stacks WHERE id=?",
    [stackId]
  );
  const stack = stacks[0];
  if (!stack) return res.status(404).json({ error: "stack not found" });

  if (!stack.is_public && stack.user_id !== req.user.id)
    return res.status(403).json({ error: "Forbidden" });

  const { rows } = await db.execute({
    sql: `SELECT * FROM cards WHERE stack_id=? ORDER BY created_at DESC`,
    args: [stackId],
  });
  res.json(rows);
});

// Karte erstellen
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

  const { rows } = await db.execute("SELECT * FROM cards WHERE id=?", [id]);
  res.status(201).json(rows[0]);
});

const boxIntervals = [0, 1, 3, 7, 16, 35]; // Index = Box, in Tagen

app.get("/api/stacks/:stackId/study/next", requireAuth, async (req, res) => {
  const { stackId } = req.params;
  const now = new Date().toISOString();
  // Nächste fällige Karte; wenn keine fällig → irgendeine Karte (zum Start)
  const { rows: dueRows } = await db.execute({
    sql: `SELECT * FROM cards WHERE stack_id=? AND due_at<=? ORDER BY due_at ASC LIMIT 1`,
    args: [stackId, now],
  });
  let card = dueRows[0];
  if (!card) {
    const { rows: randomRows } = await db.execute({
      sql: `SELECT * FROM cards WHERE stack_id=? ORDER BY RANDOM() LIMIT 1`,
      args: [stackId],
    });
    card = randomRows[0];
  }
  res.json(card || null);
});

app.post("/api/study/review", requireAuth, async (req, res) => {
  const { cardId, rating } = req.body || {}; // 'again' | 'hard' | 'good' | 'easy'
  const { rows } = await db.execute({
    sql: `SELECT * FROM cards WHERE id=?`,
    args: [cardId],
  });
  const card = rows[0];
  if (!card) return res.status(404).json({ error: "card not found" });

  let nextBox = card.box;
  let nextDue = new Date();

  switch (rating) {
    case "again":
      nextBox = 1;
      nextDue = new Date(Date.now() + 5 * 60 * 1000); // 5 Minuten
      break;
    case "hard":
      nextBox = Math.max(1, card.box);
      nextDue.setDate(nextDue.getDate() + 1);
      break;
    case "good":
      nextBox = Math.min(5, card.box + 1);
      nextDue.setDate(nextDue.getDate() + boxIntervals[nextBox]);
      break;
    case "easy":
      nextBox = Math.min(5, card.box + 2);
      nextDue.setDate(
        nextDue.getDate() + (boxIntervals[Math.min(5, nextBox)] || 3)
      );
      break;
    default:
      return res.status(400).json({ error: "invalid rating" });
  }

  const iso = nextDue.toISOString();
  const now = new Date().toISOString();
  await db.execute({
    sql: `UPDATE cards SET box=?, due_at=?, updated_at=? WHERE id=?`,
    args: [nextBox, iso, now, cardId],
  });

  const { rows: updatedRows } = await db.execute({
    sql: `SELECT * FROM cards WHERE id=?`,
    args: [cardId],
  });
  res.json(updatedRows[0]);
});



const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`✅ API läuft auf http://localhost:${port}`);
});
