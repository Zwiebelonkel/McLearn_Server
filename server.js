import "dotenv/config";
import express from "express";
import cors from "cors";
import { nanoid } from "nanoid";
import { all, one, run } from "./db.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { verifyToken, requireAuth, requireAdmin } from "./auth.js";

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",").map((s) => s.trim()),
    methods: ["GET", "POST", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "X-API-Key"],
  })
);

// Login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await db.execute({
      sql: "SELECT * FROM users WHERE username = ?",
      args: [username],
    });

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Benutzer nicht gefunden" });
    }

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

// Passwort ändern (SECURED)
app.patch("/api/users/password", requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.id; // USE ID FROM TOKEN

  try {
    const result = await db.execute({
      sql: "SELECT * FROM users WHERE id = ?",
      args: [userId],
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Benutzer nicht gefunden" });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Falsches aktuelles Passwort" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.execute({
      sql: "UPDATE users SET password = ? WHERE id = ?",
      args: [hashedPassword, userId],
    });

    res.json({ message: "Passwort erfolgreich geändert" });
  } catch (err) {
    res.status(500).json({ message: "Fehler beim Ändern des Passworts" });
  }
});

app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const hash = await bcrypt.hash(password, 10);

    // 1. Nutzer anlegen
    const result = await db.execute({
      sql: "INSERT INTO users (username, password) VALUES (?, ?)",
      args: [username, hash],
    });

    const userId = result.lastInsertRowid;

    // 2. Dorf anlegen
    const villageResult = await db.execute({
      sql: "INSERT INTO village (user_id) VALUES (?)",
      args: [userId],
    });

    const villageId = villageResult.lastInsertRowid;

    // 3. 4 Bewohner anlegen
    for (let i = 1; i <= 2; i++) {
      await db.execute({
        sql: "INSERT INTO villagers (village_id, name, level, income) VALUES (?, ?, ?, ?)",
        args: [villageId, `Bewohner ${i}`, 1, 0.5],
      });
    }

    res.status(201).json({ message: "Registrierung & Dorf erfolgreich" });
  } catch (err) {
    if (err.message.includes("UNIQUE")) {
      return res.status(409).json({ message: "Benutzername bereits vergeben" });
    }
    console.error("❌ Fehler bei Registrierung:", err);
    res.status(500).json({ message: "Fehler beim Registrieren" });
  }
});

// simple API-key auth (ein User)
app.use((req, res, next) => {
  const key = req.header("X-API-Key");
  if (!process.env.API_KEY || key === process.env.API_KEY) return next();
  return res.status(401).json({ error: "Unauthorized" });
});

// health
app.get("/api/health", (_req, res) => res.json({ ok: true }));

/** -------- Stacks -------- */
app.get("/api/stacks", async (_req, res) => {
  const rows = await all(`SELECT * FROM stacks ORDER BY created_at DESC`);
  res.json(rows);
});

app.post("/api/stacks", async (req, res) => {
  const { name } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: "name required" });
  const id = nanoid();
  const now = new Date().toISOString();
  await run(
    `INSERT INTO stacks(id,name,created_at,updated_at) VALUES(?,?,?,?)`,
    [id, name.trim(), now, now]
  );
  res.status(201).json(await one(`SELECT * FROM stacks WHERE id=?`, [id]));
});

app.patch("/api/stacks/:id", async (req, res) => {
  const { name } = req.body || {};
  const { id } = req.params;
  if (!name?.trim()) return res.status(400).json({ error: "name required" });
  const now = new Date().toISOString();
  await run(`UPDATE stacks SET name=?, updated_at=? WHERE id=?`, [
    name.trim(),
    now,
    id,
  ]);
  const row = await one(`SELECT * FROM stacks WHERE id=?`, [id]);
  if (!row) return res.status(404).json({ error: "not found" });
  res.json(row);
});

app.delete("/api/stacks/:id", async (req, res) => {
  const { id } = req.params;
  await run(`DELETE FROM stacks WHERE id=?`, [id]);
  res.status(204).end();
});

/** -------- Cards -------- */
app.get("/api/cards", async (req, res) => {
  const { stackId } = req.query;
  if (!stackId) return res.status(400).json({ error: "stackId required" });
  const rows = await all(
    `SELECT * FROM cards WHERE stack_id=? ORDER BY created_at DESC`,
    [stackId]
  );
  res.json(rows);
});

app.post("/api/cards", async (req, res) => {
  const { stack_id, front, back } = req.body || {};
  if (!stack_id || !front?.trim() || !back?.trim()) {
    return res.status(400).json({ error: "stack_id, front, back required" });
  }
  const id = nanoid();
  const now = new Date().toISOString();
  await run(
    `INSERT INTO cards(id,stack_id,front,back,box,due_at,created_at,updated_at)
     VALUES(?,?,?,?,1,?,?,?)`,
    [id, stack_id, front.trim(), back.trim(), now, now, now]
  );
  res.status(201).json(await one(`SELECT * FROM cards WHERE id=?`, [id]));
});

app.patch("/api/cards/:id", async (req, res) => {
  const { id } = req.params;
  const { front, back, stack_id } = req.body || {};
  const now = new Date().toISOString();
  const card = await one(`SELECT * FROM cards WHERE id=?`, [id]);
  if (!card) return res.status(404).json({ error: "not found" });
  await run(
    `UPDATE cards SET front=?, back=?, stack_id=?, updated_at=? WHERE id=?`,
    [
      front?.trim() ?? card.front,
      back?.trim() ?? card.back,
      stack_id ?? card.stack_id,
      now,
      id,
    ]
  );
  res.json(await one(`SELECT * FROM cards WHERE id=?`, [id]));
});

app.delete("/api/cards/:id", async (req, res) => {
  const { id } = req.params;
  await run(`DELETE FROM cards WHERE id=?`, [id]);
  res.status(204).end();
});

/** -------- Learn mode (Leitner) --------
 * Regeln: 4 Buttons -> Again, Hard, Good, Easy
 * Mapping (Box 1..5):
 *  Again -> box=1,    due=now + 5 min
 *  Hard  -> box=max(1, box),      due=now + 1 day
 *  Good  -> box=min(5, box+1),    due=now + [1,3,7,16,35] days je nach box
 *  Easy  -> box=min(5, box+2),    due=now + [3,7,16,35,35] days
 */
const boxIntervals = [0, 1, 3, 7, 16, 35]; // Index = Box, in Tagen

app.get("/api/study/next", async (req, res) => {
  const { stackId } = req.query;
  if (!stackId) return res.status(400).json({ error: "stackId required" });
  const now = new Date().toISOString();
  // Nächste fällige Karte; wenn keine fällig → irgendeine Karte (zum Start)
  let card = await one(
    `SELECT * FROM cards WHERE stack_id=? AND due_at<=? ORDER BY due_at ASC LIMIT 1`,
    [stackId, now]
  );
  if (!card) {
    card = await one(
      `SELECT * FROM cards WHERE stack_id=? ORDER BY RANDOM() LIMIT 1`,
      [stackId]
    );
  }
  res.json(card || null);
});

app.post("/api/study/review", async (req, res) => {
  const { cardId, rating } = req.body || {}; // 'again' | 'hard' | 'good' | 'easy'
  const card = await one(`SELECT * FROM cards WHERE id=?`, [cardId]);
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
  await run(`UPDATE cards SET box=?, due_at=?, updated_at=? WHERE id=?`, [
    nextBox,
    iso,
    now,
    cardId,
  ]);

  res.json(await one(`SELECT * FROM cards WHERE id=?`, [cardId]));
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`API on :${port}`);
});
