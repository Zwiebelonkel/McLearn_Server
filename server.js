import "dotenv/config";
import express from "express";
import cors from "cors";
import { nanoid } from "nanoid";
import db from "./db.js";

const app = express();

app.use(cors());
app.use(express.json());

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
  const { rows } = await db.execute(`SELECT * FROM stacks ORDER BY created_at DESC`);
  res.json(rows);
});

app.post("/api/stacks", async (req, res) => {
  const { name } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: "name required" });
  const id = nanoid();
  const now = new Date().toISOString();
  await db.execute({
    sql: `INSERT INTO stacks(id,name,created_at,updated_at) VALUES(?,?,?,?)`,
    args: [id, name.trim(), now, now],
  });
  const { rows } = await db.execute({
    sql: `SELECT * FROM stacks WHERE id=?`,
    args: [id],
  });
  res.status(201).json(rows[0]);
});

app.patch("/api/stacks/:id", async (req, res) => {
  const { name } = req.body || {};
  const { id } = req.params;
  if (!name?.trim()) return res.status(400).json({ error: "name required" });
  const now = new Date().toISOString();
  await db.execute({
    sql: `UPDATE stacks SET name=?, updated_at=? WHERE id=?`,
    args: [name.trim(), now, id],
  });
  const { rows } = await db.execute({
    sql: `SELECT * FROM stacks WHERE id=?`,
    args: [id],
  });
  if (!rows.length) return res.status(404).json({ error: "not found" });
  res.json(rows[0]);
});

app.delete("/api/stacks/:id", async (req, res) => {
  const { id } = req.params;
  await db.execute({ sql: `DELETE FROM stacks WHERE id=?`, args: [id] });
  res.status(204).end();
});

/** -------- Cards -------- */
app.get("/api/cards", async (req, res) => {
  const { stackId } = req.query;
  if (!stackId) return res.status(400).json({ error: "stackId required" });
  const { rows } = await db.execute({
    sql: `SELECT * FROM cards WHERE stack_id=? ORDER BY created_at DESC`,
    args: [stackId],
  });
  res.json(rows);
});

app.post("/api/cards", async (req, res) => {
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

app.patch("/api/cards/:id", async (req, res) => {
  const { id } = req.params;
  const { front, back, stack_id } = req.body || {};
  const now = new Date().toISOString();
  const { rows: cardRows } = await db.execute({
    sql: `SELECT * FROM cards WHERE id=?`,
    args: [id],
  });
  const card = cardRows[0];
  if (!card) return res.status(404).json({ error: "not found" });
  await db.execute({
    sql: `UPDATE cards SET front=?, back=?, stack_id=?, updated_at=? WHERE id=?`,
    args: [
      front?.trim() ?? card.front,
      back?.trim() ?? card.back,
      stack_id ?? card.stack_id,
      now,
      id,
    ],
  });
  const { rows } = await db.execute({
    sql: `SELECT * FROM cards WHERE id=?`,
    args: [id],
  });
  res.json(rows[0]);
});

app.delete("/api/cards/:id", async (req, res) => {
  const { id } = req.params;
  await db.execute({ sql: `DELETE FROM cards WHERE id=?`, args: [id] });
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

app.post("/api/study/review", async (req, res) => {
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
  console.log(`API on :${port}`);
});
