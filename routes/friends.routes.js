import { Router } from "express";
import db from "../db.js";
import { requireAuth } from "../middleware/requireAuth.js";

const router = Router();

// Get friends
router.get("/", requireAuth, async (req, res) => {
  const userId = req.user.id;

  const { rows } = await db.execute({
    sql: `
      SELECT u.id, u.username AS name
      FROM friends f
      JOIN users u ON (u.id = f.friend_id)
      WHERE f.user_id = ?
      UNION
      SELECT u.id, u.username AS name
      FROM friends f
      JOIN users u ON (u.id = f.user_id)
      WHERE f.friend_id = ?
    `,
    args: [userId, userId],
  });

  res.json(rows);
});

// Get friend requests
router.get("/requests", requireAuth, async (req, res) => {
  const userId = req.user.id;

  const { rows } = await db.execute({
    sql: `
      SELECT fr.id, u.id as sender_id, u.username AS name
      FROM friend_requests fr
      JOIN users u ON u.id = fr.sender_id
      WHERE fr.receiver_id = ?
    `,
    args: [userId],
  });

  res.json(rows);
});

// Send friend request
router.post("/requests", requireAuth, async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: "username required" });

  const { rows } = await db.execute({
    sql: "SELECT id FROM users WHERE username = ?",
    args: [username],
  });
  const target = rows[0];
  if (!target) return res.status(404).json({ error: "user not found" });

  const userId = req.user.id;
  if (target.id === userId)
    return res.status(400).json({ error: "cannot add yourself" });

  const { rows: existing } = await db.execute({
    sql: `
      SELECT * FROM friend_requests 
      WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
    `,
    args: [userId, target.id, target.id, userId],
  });
  const { rows: alreadyFriends } = await db.execute({
    sql: `
      SELECT * FROM friends
      WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)
    `,
    args: [userId, target.id, target.id, userId],
  });
  if (existing.length || alreadyFriends.length)
    return res.status(409).json({ error: "already requested or friends" });

  await db.execute({
    sql: "INSERT INTO friend_requests (sender_id, receiver_id) VALUES (?, ?)",
    args: [userId, target.id],
  });
  res.status(201).json({ success: true });
});

// Accept friend request
router.put("/requests/:senderId", requireAuth, async (req, res) => {
  const receiverId = req.user.id;
  const { senderId } = req.params;

  await db.execute({
    sql: `
      INSERT INTO friends (user_id, friend_id)
      VALUES (?, ?), (?, ?)
    `,
    args: [receiverId, senderId, senderId, receiverId],
  });

  await db.execute({
    sql: `
      DELETE FROM friend_requests 
      WHERE sender_id=? AND receiver_id=?
    `,
    args: [senderId, receiverId],
  });

  res.json({ success: true });
});

// Decline friend request
router.delete("/requests/:senderId", requireAuth, async (req, res) => {
  const receiverId = req.user.id;
  const { senderId } = req.params;

  await db.execute({
    sql: `
      DELETE FROM friend_requests 
      WHERE sender_id=? AND receiver_id=?
    `,
    args: [senderId, receiverId],
  });

  res.json({ success: true });
});

// Remove friend
router.delete("/:friendId", requireAuth, async (req, res) => {
  const userId = req.user.id;
  const { friendId } = req.params;

  await db.execute({
    sql: `
      DELETE FROM friends
      WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)
    `,
    args: [userId, friendId, friendId, userId],
  });

  res.json({ success: true });
});

export default router;
