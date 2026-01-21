
import { Router } from "express";
import { nanoid } from "nanoid";
import db from "../db.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { optionalAuth } from "../middleware/optionalAuth.js";

const router = Router();

// Get all stacks (public + user's own)
router.get("/", optionalAuth, async (req, res) => {
  const userId = req.user?.id;

  let sql = `
    SELECT DISTINCT
      s.id,
      s.name,
      s.is_public,
      s.created_at,
      s.updated_at,
      s.user_id,
      u.username as owner_name,
      COUNT(DISTINCT c.id) as card_amount
    FROM stacks s
    JOIN users u ON s.user_id = u.id
    LEFT JOIN cards c ON c.stack_id = s.id
    LEFT JOIN stack_collaborators sc ON s.id = sc.stack_id
  `;

  const args = [];
  if (userId) {
    sql += " WHERE s.is_public = 1 OR s.user_id = ? OR sc.user_id = ?";
    args.push(userId, userId);
  } else {
    sql += " WHERE s.is_public = 1";
  }

  sql += " GROUP BY s.id ORDER BY s.created_at DESC";

  const { rows } = await db.execute({ sql, args });
  
  // For each stack, load its collaborators and ratings
  const stacksWithCollaborators = await Promise.all(
    rows.map(async (stack) => {
      // Get collaborators
      const { rows: collabRows } = await db.execute({
        sql: `
          SELECT sc.id, sc.user_id, u.username as user_name
          FROM stack_collaborators sc
          JOIN users u ON sc.user_id = u.id
          WHERE sc.stack_id = ?
        `,
        args: [stack.id]
      });
      
      // Get rating statistics
      const { rows: ratingStats } = await db.execute({
        sql: `
          SELECT 
            AVG(rating) as average_rating,
            COUNT(*) as rating_count
          FROM stack_ratings
          WHERE stack_id = ?
        `,
        args: [stack.id]
      });
      
      // Get user's own rating if logged in
      let userRating = null;
      if (userId) {
        const { rows: userRatingRows } = await db.execute({
          sql: `SELECT rating FROM stack_ratings WHERE stack_id = ? AND user_id = ?`,
          args: [stack.id, userId]
        });
        userRating = userRatingRows.length > 0 ? userRatingRows[0].rating : null;
      }
      
      return {
        ...stack,
        collaborators: collabRows,
        average_rating: ratingStats[0]?.average_rating || null,
        rating_count: ratingStats[0]?.rating_count || 0,
        user_rating: userRating
      };
    })
  );
  
  res.json(stacksWithCollaborators);
});

// Create stack
router.post("/", requireAuth, async (req, res) => {
  const { name, is_public } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: "name required" });

  const id = nanoid();
  const now = new Date().toISOString();

  await db.execute({
    sql: `INSERT INTO stacks(id,user_id,name,is_public,created_at,updated_at)
          VALUES(?,?,?,?,?,?)`,
    args: [id, req.user.id, name.trim(), is_public ? 1 : 0, now, now],
  });

  const { rows } = await db.execute(
    "SELECT s.*, u.username as owner_name FROM stacks s JOIN users u ON s.user_id = u.id WHERE s.id=?",
    [id]
  );
  res.status(201).json(rows[0]);
});

// Get single stack
router.get("/:id", optionalAuth, async (req, res) => {
  const { id } = req.params;
  const { rows } = await db.execute(
    "SELECT s.*, u.username as owner_name FROM stacks s JOIN users u ON s.user_id = u.id WHERE s.id=?",
    [id]
  );
  const stack = rows[0];
  if (!stack) return res.status(404).json({ error: "not found" });

  if (!stack.is_public) {
    if (!req.user) {
      return res.status(403).json({ error: "Forbidden - Login required" });
    }
    if (stack.user_id !== req.user.id) {
      return res.status(403).json({ error: "Forbidden" });
    }
  }

  res.json(stack);
});

// Update stack
router.patch("/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { name, is_public } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: "name required" });

  const now = new Date().toISOString();
  await db.execute({
    sql: `UPDATE stacks SET name=?, is_public=?, updated_at=?
          WHERE id=? AND user_id=?`,
    args: [name.trim(), is_public ? 1 : 0, now, id, req.user.id],
  });

  const { rows } = await db.execute(
    "SELECT s.*, u.username as owner_name FROM stacks s JOIN users u ON s.user_id = u.id WHERE s.id=?",
    [id]
  );
  if (!rows.length) return res.status(404).json({ error: "not found" });
  res.json(rows[0]);
});

// Delete stack
router.delete("/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  await db.execute({
    sql: `DELETE FROM stacks WHERE id=? AND user_id=?`,
    args: [id, req.user.id],
  });
  res.status(204).end();
});

// Rate a stack
router.post("/:stackId/rate", requireAuth, async (req, res) => {
  const { stackId } = req.params;
  const { rating } = req.body;
  const userId = req.user.id;

  // Validate rating
  if (!rating || rating < 1 || rating > 5) {
    return res.status(400).json({ error: "Rating must be between 1 and 5" });
  }

  // Check if stack exists and is accessible
  const { rows: stackRows } = await db.execute(
    "SELECT * FROM stacks WHERE id = ?",
    [stackId]
  );
  const stack = stackRows[0];
  if (!stack) {
    return res.status(404).json({ error: "Stack not found" });
  }

  // Can't rate your own stack
  if (stack.user_id === userId) {
    return res.status(403).json({ error: "You cannot rate your own stack" });
  }

  // Only allow rating public stacks or stacks shared with user
  if (!stack.is_public) {
    const { rows: collaboratorRows } = await db.execute(
      "SELECT 1 FROM stack_collaborators WHERE stack_id = ? AND user_id = ?",
      [stackId, userId]
    );
    if (collaboratorRows.length === 0) {
      return res.status(403).json({ error: "You can only rate public stacks or stacks shared with you" });
    }
  }

  const now = new Date().toISOString();

  try {
    // Check if user has already rated this stack
    const { rows: existingRating } = await db.execute({
      sql: "SELECT id FROM stack_ratings WHERE stack_id = ? AND user_id = ?",
      args: [stackId, userId]
    });

    if (existingRating.length > 0) {
      // Update existing rating
      await db.execute({
        sql: "UPDATE stack_ratings SET rating = ?, updated_at = ? WHERE stack_id = ? AND user_id = ?",
        args: [rating, now, stackId, userId]
      });
    } else {
      // Insert new rating
      await db.execute({
        sql: `INSERT INTO stack_ratings (stack_id, user_id, rating, created_at, updated_at)
              VALUES (?, ?, ?, ?, ?)`,
        args: [stackId, userId, rating, now, now]
      });
    }

    // Get updated rating statistics
    const { rows: ratingStats } = await db.execute({
      sql: `
        SELECT 
          AVG(rating) as average_rating,
          COUNT(*) as rating_count
        FROM stack_ratings
        WHERE stack_id = ?
      `,
      args: [stackId]
    });

    // Return updated stack with new ratings
    res.json({
      id: stack.id,
      name: stack.name,
      average_rating: ratingStats[0]?.average_rating || null,
      rating_count: ratingStats[0]?.rating_count || 0,
      user_rating: rating
    });

  } catch (err) {
    console.error("Error rating stack:", err);
    res.status(500).json({ error: "Failed to rate stack" });
  }
});

// Get stack ratings
router.get("/:stackId/ratings", optionalAuth, async (req, res) => {
  const { stackId } = req.params;

  // Check if stack exists
  const { rows: stackRows } = await db.execute(
    "SELECT * FROM stacks WHERE id = ?",
    [stackId]
  );
  if (stackRows.length === 0) {
    return res.status(404).json({ error: "Stack not found" });
  }

  // Get rating statistics
  const { rows: ratingStats } = await db.execute({
    sql: `
      SELECT 
        AVG(rating) as average_rating,
        COUNT(*) as rating_count,
        SUM(CASE WHEN rating = 5 THEN 1 ELSE 0 END) as five_stars,
        SUM(CASE WHEN rating = 4 THEN 1 ELSE 0 END) as four_stars,
        SUM(CASE WHEN rating = 3 THEN 1 ELSE 0 END) as three_stars,
        SUM(CASE WHEN rating = 2 THEN 1 ELSE 0 END) as two_stars,
        SUM(CASE WHEN rating = 1 THEN 1 ELSE 0 END) as one_star
      FROM stack_ratings
      WHERE stack_id = ?
    `,
    args: [stackId]
  });

  // Get user's own rating if logged in
  let userRating = null;
  if (req.user) {
    const { rows: userRatingRows } = await db.execute({
      sql: `SELECT rating FROM stack_ratings WHERE stack_id = ? AND user_id = ?`,
      args: [stackId, req.user.id]
    });
    userRating = userRatingRows.length > 0 ? userRatingRows[0].rating : null;
  }

  res.json({
    ...ratingStats[0],
    user_rating: userRating
  });
});

export default router;
