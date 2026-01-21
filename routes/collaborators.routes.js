import { Router } from "express";
import db from "../db.js";
import { requireAuth } from "../middleware/requireAuth.js";

const router = Router();

// Get collaborators for a stack
router.get("/:stackId", requireAuth, async (req, res) => {
  const { stackId } = req.params;
  const { rows } = await db.execute({
    sql: `
      SELECT sc.id, sc.user_id, u.username as user_name
      FROM stack_collaborators sc
      JOIN users u ON sc.user_id = u.id
      WHERE sc.stack_id = ?
    `,
    args: [stackId],
  });
  res.json(rows);
});

// Add collaborator
router.post("/:stackId", requireAuth, async (req, res) => {
  const { stackId } = req.params;
  const { userId } = req.body;

  const { rows: stackRows } = await db.execute(
    "SELECT user_id FROM stacks WHERE id = ?",
    [stackId]
  );
  if (stackRows.length === 0)
    return res.status(404).json({ error: "Stack not found" });
  if (stackRows[0].user_id !== req.user.id)
    return res.status(403).json({ error: "Forbidden" });

  try {
    const { lastInsertRowid } = await db.execute({
      sql: "INSERT INTO stack_collaborators (stack_id, user_id) VALUES (?, ?)",
      args: [stackId, userId],
    });
    const { rows } = await db.execute({
      sql: `
        SELECT sc.id, sc.user_id, u.username as user_name
        FROM stack_collaborators sc
        JOIN users u ON sc.user_id = u.id
        WHERE sc.id = ?
      `,
      args: [lastInsertRowid],
    });
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.message.includes("UNIQUE")) {
      return res
        .status(409)
        .json({ error: "User is already a collaborator." });
    }
    res.status(500).json({ error: "Failed to add collaborator." });
  }
});

// Remove collaborator
router.delete("/:stackId/:collaboratorId", requireAuth, async (req, res) => {
  const { stackId, collaboratorId } = req.params;

  const { rows: stackRows } = await db.execute(
    "SELECT user_id FROM stacks WHERE id = ?",
    [stackId]
  );
  if (stackRows.length === 0)
    return res.status(404).json({ error: "Stack not found" });
  if (stackRows[0].user_id !== req.user.id)
    return res.status(403).json({ error: "Forbidden" });

  await db.execute({
    sql: "DELETE FROM stack_collaborators WHERE id = ?",
    args: [collaboratorId],
  });

  res.status(204).end();
});

export default router;
