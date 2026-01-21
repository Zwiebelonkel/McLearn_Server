import { Router } from "express";
import { nanoid } from "nanoid";
import db from "../db.js";
import { requireAuth } from "../middleware/requireAuth.js";

const router = Router();

// Get scribblepad
router.get("/", requireAuth, async (req, res) => {
  const userId = req.user.id;

  try {
    const { rows } = await db.execute({
      sql: "SELECT * FROM scribblepad WHERE user_id = ?",
      args: [userId],
    });

    if (rows.length === 0) {
      return res.status(404).json({ error: "ScribblePad not found" });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error("Error fetching scribblepad:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Save scribblepad
router.post("/", requireAuth, async (req, res) => {
  const userId = req.user.id;
  const { content } = req.body;

  if (typeof content !== "string") {
    return res.status(400).json({ error: "Content must be a string" });
  }

  try {
    const now = new Date().toISOString();

    const { rows: existing } = await db.execute({
      sql: "SELECT * FROM scribblepad WHERE user_id = ?",
      args: [userId],
    });

    if (existing.length > 0) {
      await db.execute({
        sql: "UPDATE scribblepad SET content = ?, updated_at = ? WHERE user_id = ?",
        args: [content, now, userId],
      });

      const { rows: updated } = await db.execute({
        sql: "SELECT * FROM scribblepad WHERE user_id = ?",
        args: [userId],
      });

      res.json(updated[0]);
    } else {
      const id = nanoid();
      await db.execute({
        sql: `INSERT INTO scribblepad (id, user_id, content, created_at, updated_at)
              VALUES (?, ?, ?, ?, ?)`,
        args: [id, userId, content, now, now],
      });

      const { rows: created } = await db.execute({
        sql: "SELECT * FROM scribblepad WHERE id = ?",
        args: [id],
      });

      res.status(201).json(created[0]);
    }
  } catch (err) {
    console.error("Error saving scribblepad:", err);
    res.status(500).json({ error: "Server error" });
  }
});

export default router;
