import { Router } from "express";
import db from "../db.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { requireAdmin } from "../middleware/requireAdmin.js";

const router = Router();

// Get all users
router.get("/users", requireAuth, requireAdmin, async (req, res) => {
  const { rows } = await db.execute({
    sql: `
      SELECT 
        u.id,
        u.username,
        u.role,
        COUNT(DISTINCT s.id) AS stack_count,
        COUNT(DISTINCT c.id) AS card_count
      FROM users u
      LEFT JOIN stacks s ON s.user_id = u.id
      LEFT JOIN cards c ON c.stack_id = s.id
      GROUP BY u.id
      ORDER BY u.id DESC
    `,
  });

  res.json(rows);
});

// Get all stacks (admin view)
router.get("/stacks", requireAuth, requireAdmin, async (req, res) => {
  const { rows } = await db.execute({
    sql: `
      SELECT 
        s.id,
        s.name,
        s.user_id,
        s.is_public,
        s.created_at,
        s.updated_at,
        u.username AS owner_name,
        COUNT(c.id) AS card_amount
      FROM stacks s
      JOIN users u ON s.user_id = u.id
      LEFT JOIN cards c ON c.stack_id = s.id
      GROUP BY s.id
      ORDER BY s.created_at DESC
    `,
  });

  res.json(rows);
});

// Delete user
router.delete("/users/:userId", requireAuth, requireAdmin, async (req, res) => {
  const { userId } = req.params;

  // Check if trying to delete admin
  const { rows: userRows } = await db.execute({
    sql: "SELECT username FROM users WHERE id = ?",
    args: [userId],
  });

  if (userRows.length === 0) {
    return res.status(404).json({ error: "User not found" });
  }

  const username = userRows[0].username;
  if (username === "Luca" || username === "McLearn") {
    return res.status(403).json({ error: "Cannot delete admin users" });
  }

  // Delete user (cascade will handle stacks, cards, etc.)
  await db.execute({
    sql: "DELETE FROM users WHERE id = ?",
    args: [userId],
  });

  res.status(204).end();
});

// Delete stack
router.delete("/stacks/:stackId", requireAuth, requireAdmin, async (req, res) => {
  const { stackId } = req.params;

  await db.execute({
    sql: "DELETE FROM stacks WHERE id = ?",
    args: [stackId],
  });

  res.status(204).end();
});

// Update stack visibility
router.patch("/stacks/:stackId", requireAuth, requireAdmin, async (req, res) => {
  const { stackId } = req.params;
  const { is_public } = req.body;

  const now = new Date().toISOString();

  await db.execute({
    sql: "UPDATE stacks SET is_public = ?, updated_at = ? WHERE id = ?",
    args: [is_public ? 1 : 0, now, stackId],
  });

  const { rows } = await db.execute({
    sql: `
      SELECT 
        s.*,
        u.username AS owner_name,
        COUNT(c.id) AS card_amount
      FROM stacks s
      JOIN users u ON s.user_id = u.id
      LEFT JOIN cards c ON c.stack_id = s.id
      WHERE s.id = ?
      GROUP BY s.id
    `,
    args: [stackId],
  });

  if (rows.length === 0) {
    return res.status(404).json({ error: "Stack not found" });
  }

  res.json(rows[0]);
});

// Transfer stack ownership
router.patch("/stacks/:stackId/transfer", requireAuth, requireAdmin, async (req, res) => {
  const { stackId } = req.params;
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: "Username required" });
  }

  // Find target user
  const { rows: userRows } = await db.execute({
    sql: "SELECT id FROM users WHERE username = ?",
    args: [username],
  });

  if (userRows.length === 0) {
    return res.status(404).json({ error: "User not found" });
  }

  const newUserId = userRows[0].id;
  const now = new Date().toISOString();

  // Transfer stack
  await db.execute({
    sql: "UPDATE stacks SET user_id = ?, updated_at = ? WHERE id = ?",
    args: [newUserId, now, stackId],
  });

  const { rows } = await db.execute({
    sql: `
      SELECT 
        s.*,
        u.username AS owner_name,
        COUNT(c.id) AS card_amount
      FROM stacks s
      JOIN users u ON s.user_id = u.id
      LEFT JOIN cards c ON c.stack_id = s.id
      WHERE s.id = ?
      GROUP BY s.id
    `,
    args: [stackId],
  });

  if (rows.length === 0) {
    return res.status(404).json({ error: "Stack not found" });
  }

  res.json(rows[0]);
});

// Get admin statistics
router.get("/statistics", requireAuth, requireAdmin, async (req, res) => {
  // Total users
  const { rows: userStats } = await db.execute({ sql: "SELECT COUNT(*) AS total FROM users" });

  // Total stacks
  const { rows: stackStats } = await db.execute({
    sql: `
      SELECT COUNT(*) AS total,
             SUM(CASE WHEN is_public = 1 THEN 1 ELSE 0 END) AS public
      FROM stacks
    `,
  });

  // Total cards
  const { rows: cardStats } = await db.execute({ sql: "SELECT COUNT(*) AS total FROM cards" });

  // Total reviews
  const { rows: reviewStats } = await db.execute({ sql: "SELECT COUNT(*) AS total FROM card_reviews" });

  // Recent activity (last 7 days)
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();

  const { rows: recentUsers } = await db.execute({
    sql: "SELECT COUNT(*) AS count FROM users WHERE created_at >= ?",
    args: [sevenDaysAgo],
  });

  const { rows: recentStacks } = await db.execute({
    sql: "SELECT COUNT(*) AS count FROM stacks WHERE created_at >= ?",
    args: [sevenDaysAgo],
  });

  const { rows: recentReviews } = await db.execute({
    sql: "SELECT COUNT(*) AS count FROM card_reviews WHERE created_at >= ?",
    args: [sevenDaysAgo],
  });

  res.json({
    total: {
      users: userStats[0].total,
      stacks: stackStats[0].total,
      publicStacks: stackStats[0].public,
      cards: cardStats[0].total,
      reviews: reviewStats[0].total,
    },
    recent: {
      users: recentUsers[0].count,
      stacks: recentStacks[0].count,
      reviews: recentReviews[0].count,
    },
  });
});

export default router;
