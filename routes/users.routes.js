import { Router } from "express";
import db from "../db.js";
import { requireAuth } from "../middleware/requireAuth.js";

const router = Router();

// Search users
router.get("/search", requireAuth, async (req, res) => {
  const { query } = req.query;
  if (!query) return res.json([]);

  const { rows } = await db.execute({
    sql: "SELECT id, username as name, username as email FROM users WHERE username LIKE ? AND id != ?",
    args: [`%${query}%`, req.user.id],
  });
  res.json(rows);
});

// Get user by ID
router.get("/:id", async (req, res) => {
  const { id } = req.params;

  const { rows } = await db.execute({
    sql: `
      SELECT id, username AS name
      FROM users
      WHERE id = ?
    `,
    args: [id],
  });

  if (rows.length === 0) {
    return res.status(404).json({ error: "user not found" });
  }

  res.json(rows[0]);
});

export default router;
