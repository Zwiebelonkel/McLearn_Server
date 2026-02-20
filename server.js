import "dotenv/config";
import express from "express";
import cors from "cors";
import { nanoid } from "nanoid";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import db from "./db.js";
import { requireAuth, optionalAuth } from "./auth.js";

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || "fallback-secret";

app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-API-Key"],
  })
);

app.use(express.json());
// Default is 100kb, we need at least 10mb for images
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

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
      { expiresIn: "24h" }
    );

    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ message: "Login-Fehler" });
  }
});

// Einfacher Test-Endpunkt
app.get('/api/test', (req, res) => {
  res.status(200).send('ok');
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

/* ========== USERS ========== */
app.get("/api/users/search", requireAuth, async (req, res) => {
  const { query } = req.query;
  if (!query) return res.json([]);

  const { rows } = await db.execute({
    sql: "SELECT id, username as name, username as email FROM users WHERE username LIKE ? AND id != ?",
    args: [`%${query}%`, req.user.id],
  });
  res.json(rows);
});

/* ========== HEALTH ========== */
app.get("/api/health", (_req, res) => res.json({ ok: true }));

/* ========== STACKS ========== */

// Alle öffentlichen Stacks, plus eigene für eingeloggte Nutzer
// UPDATED: Now includes collaborators as full objects and ratings
app.get("/api/stacks", optionalAuth, async (req, res) => {
  const userId = req.user?.id;

let sql = `
  SELECT DISTINCT
    s.id,
    s.name,
    s.description,
    s.cover_image,
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

// Stack erstellen
app.post("/api/stacks", requireAuth, async (req, res) => {
  const { name, is_public, cover_image, description } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: "name required" });

  const id = nanoid();
  const now = new Date().toISOString();
  
  // ✅ NEW: Include cover_image in INSERT
await db.execute({
  sql: `
    INSERT INTO stacks(id, user_id, name, is_public, cover_image, description, created_at, updated_at)
    VALUES(?, ?, ?, ?, ?, ?, ?, ?)
  `,
  args: [id, req.user.id, name.trim(), is_public ? 1 : 0, cover_image || null, description || null, now, now],
});


  const { rows } = await db.execute(
    "SELECT s.*, u.username as owner_name FROM stacks s JOIN users u ON s.user_id = u.id WHERE s.id=?",
    [id]
  );
  res.status(201).json(rows[0]);
});

// Einzelnen Stack holen
app.get("/api/stacks/:id", optionalAuth, async (req, res) => {
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

// ⭐ Rate a Stack (NEW)
app.post("/api/stacks/:stackId/rate", requireAuth, async (req, res) => {
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

// Get stack ratings (NEW - optional, for detailed rating view)
app.get("/api/stacks/:stackId/ratings", optionalAuth, async (req, res) => {
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

// 📊 Stack Statistics
app.get("/api/stacks/:stackId/statistics", optionalAuth, async (req, res) => {
  const { stackId } = req.params;

  // Check access permissions
  const { rows: stackRows } = await db.execute(
    "SELECT * FROM stacks WHERE id = ?",
    [stackId]
  );
  const stack = stackRows[0];
  if (!stack) return res.status(404).json({ error: "Stack not found" });

  if (!stack.is_public) {
    if (!req.user) {
      return res.status(403).json({ error: "Forbidden - Login required" });
    }
    if (stack.user_id !== req.user.id) {
      const { rows: collaboratorRows } = await db.execute(
        "SELECT 1 FROM stack_collaborators WHERE stack_id = ? AND user_id = ?",
        [stackId, req.user.id]
      );
      if (collaboratorRows.length === 0) {
        return res.status(403).json({ error: "Forbidden" });
      }
    }
  }

  // Get overall statistics
  const { rows: overallStats } = await db.execute({
    sql: `
      SELECT 
        COUNT(*) as total_cards,
        AVG(box) as average_box,
        SUM(review_count) as total_reviews,
        SUM(again_count) as total_again,
        SUM(hard_count) as total_hard,
        SUM(good_count) as total_good,
        SUM(easy_count) as total_easy
      FROM cards 
      WHERE stack_id = ?
    `,
    args: [stackId],
  });

  // Most reviewed cards (top 10)
  const { rows: mostReviewed } = await db.execute({
    sql: `
      SELECT id, front, back, review_count, box
      FROM cards 
      WHERE stack_id = ? AND review_count > 0
      ORDER BY review_count DESC 
      LIMIT 5
    `,
    args: [stackId],
  });

  // Hardest cards (most "again" ratings, top 10)
  const { rows: hardestCards } = await db.execute({
    sql: `
      SELECT id, front, back, hard_count, review_count, box
      FROM cards 
      WHERE stack_id = ? AND hard_count > 0
      ORDER BY hard_count DESC, review_count DESC
      LIMIT 5
    `,
    args: [stackId],
  });

  // Easiest cards (most "easy" ratings, top 10)
  const { rows: easiestCards } = await db.execute({
    sql: `
      SELECT id, front, back, easy_count, review_count, box
      FROM cards 
      WHERE stack_id = ? AND easy_count > 0
      ORDER BY easy_count DESC, box DESC
      LIMIT 5
    `,
    args: [stackId],
  });

  // Box distribution
  const { rows: boxDistribution } = await db.execute({
    sql: `
      SELECT 
        box,
        COUNT(*) as count
      FROM cards 
      WHERE stack_id = ?
      GROUP BY box
      ORDER BY box
    `,
    args: [stackId],
  });

  // Recent review activity (last 30 days)
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const { rows: recentActivity } = await db.execute({
    sql: `
      SELECT 
        DATE(created_at) as date,
        COUNT(*) as review_count,
        SUM(CASE WHEN rating = 'again' THEN 1 ELSE 0 END) as again_count,
        SUM(CASE WHEN rating = 'hard' THEN 1 ELSE 0 END) as hard_count,
        SUM(CASE WHEN rating = 'good' THEN 1 ELSE 0 END) as good_count,
        SUM(CASE WHEN rating = 'easy' THEN 1 ELSE 0 END) as easy_count
      FROM card_reviews
      WHERE stack_id = ? AND created_at >= ?
      GROUP BY DATE(created_at)
      ORDER BY date DESC
    `,
    args: [stackId, thirtyDaysAgo],
  });

  res.json({
    overall: overallStats[0],
    mostReviewed,
    hardestCards,
    easiestCards,
    boxDistribution,
    recentActivity,
  });
});

// Stack bearbeiten
app.patch("/api/stacks/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { name, is_public, cover_image, description } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: "name required" });

  const now = new Date().toISOString();
  
  // ✅ NEW: Include cover_image in UPDATE
  await db.execute({
    sql: `UPDATE stacks SET name=?, is_public=?, cover_image=?,description=?, updated_at=?
          WHERE id=? AND user_id=?`,
    args: [name.trim(), is_public ? 1 : 0, cover_image || null, description || null, now, id, req.user.id],
  });

  const { rows } = await db.execute(
    "SELECT s.*, u.username as owner_name FROM stacks s JOIN users u ON s.user_id = u.id WHERE s.id=?",
    [id]
  );
  if (!rows.length) return res.status(404).json({ error: "not found" });
  res.json(rows[0]);
});

// Stack löschen
app.delete("/api/stacks/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    await db.execute({
      sql: `DELETE FROM stacks WHERE id=? AND user_id=?`,
      args: [id, req.user.id],
    });
    res.status(204).end();
  } catch (err) {
    console.error("Error deleting stack:", err);
    res.status(500).json({ error: "Failed to delete stack: " + err.message });
  }
});

/* ========== COLLABORATORS ========== */

app.get("/api/stacks/:stackId/collaborators", requireAuth, async (req, res) => {
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

app.post(
  "/api/stacks/:stackId/collaborators",
  requireAuth,
  async (req, res) => {
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
  }
);

app.delete(
  "/api/stacks/:stackId/collaborators/:collaboratorId",
  requireAuth,
  async (req, res) => {
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
  }
);

/* ========== CARDS ========== */

// Karten eines Stacks holen
app.get("/api/cards", optionalAuth, async (req, res) => {
  const { stackId } = req.query;
  if (!stackId) return res.status(400).json({ error: "stackId required" });

  const { rows: stacks } = await db.execute("SELECT * FROM stacks WHERE id=?", [
    stackId,
  ]);
  const stack = stacks[0];
  if (!stack) return res.status(404).json({ error: "stack not found" });

  if (!stack.is_public) {
    if (!req.user) {
      return res.status(403).json({ error: "Forbidden - Login required" });
    }
    if (stack.user_id !== req.user.id) {
      const { rows: collaboratorRows } = await db.execute(
        "SELECT 1 FROM stack_collaborators WHERE stack_id = ? AND user_id = ?",
        [stackId, req.user.id]
      );
      if (collaboratorRows.length === 0) {
        return res.status(403).json({ error: "Forbidden" });
      }
    }
  }

  const { rows } = await db.execute({
    sql: `SELECT * FROM cards WHERE stack_id=? ORDER BY created_at DESC`,
    args: [stackId],
  });
  res.json(rows);
});

// Karte erstellen
app.post("/api/cards", requireAuth, async (req, res) => {
  const { stack_id, front, back, front_image } = req.body || {};
  if (!stack_id || !front?.trim() || !back?.trim()) {
    return res.status(400).json({ error: "stack_id, front, back required" });
  }

  const { rows: stacks } = await db.execute("SELECT * FROM stacks WHERE id=?", [
    stack_id,
  ]);
  const stack = stacks[0];
  if (!stack) return res.status(404).json({ error: "stack not found" });

  if (stack.user_id !== req.user.id) {
    const { rows: collaboratorRows } = await db.execute(
      "SELECT 1 FROM stack_collaborators WHERE stack_id = ? AND user_id = ?",
      [stack_id, req.user.id]
    );
    if (collaboratorRows.length === 0) {
      return res.status(403).json({ error: "Forbidden" });
    }
  }

  const id = nanoid();
  const now = new Date().toISOString();
  
  const imageValue = front_image && front_image.trim() ? front_image.trim() : null;
  
  await db.execute({
    sql: `INSERT INTO cards(id,stack_id,front,back,front_image,box,due_at,review_count,again_count,hard_count,good_count,easy_count,created_at,updated_at)
     VALUES(?,?,?,?,?,1,?,0,0,0,0,0,?,?)`,
    args: [
      id,
      stack_id,
      front.trim(),
      back.trim(),
      imageValue,
      now,
      now,
      now,
    ],
  });

  const { rows } = await db.execute("SELECT * FROM cards WHERE id=?", [id]);
  res.status(201).json(rows[0]);
});

const boxIntervals = [0, 1, 3, 7, 16, 35];

app.get("/api/stacks/:stackId/study/next", optionalAuth, async (req, res) => {
  const { stackId } = req.params;

  const { rows: stacks } = await db.execute(
    "SELECT * FROM stacks WHERE id = ?",
    [stackId]
  );
  const stack = stacks[0];
  if (!stack) {
    return res.status(404).json({ error: "stack not found" });
  }

  // 🔐 Access Control
  if (!stack.is_public) {
    if (!req.user) {
      return res.status(403).json({ error: "Forbidden - Login required" });
    }
    if (stack.user_id !== req.user.id) {
      const { rows: collaboratorRows } = await db.execute(
        "SELECT 1 FROM stack_collaborators WHERE stack_id = ? AND user_id = ?",
        [stackId, req.user.id]
      );
      if (collaboratorRows.length === 0) {
        return res.status(403).json({ error: "Forbidden" });
      }
    }
  }

  res.setHeader("Cache-Control", "no-store");

  const now = new Date().toISOString();
  let card = null;

  // 🎲 Entscheidung: neu vs alt
  const roll = Math.random();
  const OLD_CARD_CHANCE = 0.25; // 25% alte Karten

  // =====================================================
  // 1️⃣ Alte Karten (fällig + schwierig priorisiert)
  // =====================================================
  if (roll < OLD_CARD_CHANCE) {
    const { rows: oldCards } = await db.execute({
      sql: `
        SELECT *,
          (hard_count * 3) AS difficulty_score,
          (julianday('now') - julianday(due_at)) * 24 AS hours_overdue
        FROM cards
        WHERE stack_id = ?
          AND review_count > 0
          AND due_at <= ?
        ORDER BY
          hours_overdue DESC,
          difficulty_score DESC,
          RANDOM()
        LIMIT 1
      `,
      args: [stackId, now],
    });

    if (oldCards.length > 0) {
      card = oldCards[0];
    }
  }

  // =====================================================
  // 2️⃣ Neue Karten (SPAM ERLAUBT)
  // =====================================================
  if (!card) {
    const { rows: newCards } = await db.execute({
      sql: `
        SELECT *
        FROM cards
        WHERE stack_id = ?
          AND review_count = 0
        ORDER BY RANDOM()
        LIMIT 1
      `,
      args: [stackId],
    });

    if (newCards.length > 0) {
      card = newCards[0];
    }
  }

  // =====================================================
  // 3️⃣ Fallback: irgendeine alte Karte
  // =====================================================
  if (!card) {
    const { rows: anyOld } = await db.execute({
      sql: `
        SELECT *
        FROM cards
        WHERE stack_id = ?
          AND review_count > 0
        ORDER BY RANDOM()
        LIMIT 1
      `,
      args: [stackId],
    });

    if (anyOld.length > 0) {
      card = anyOld[0];
    }
  }

  // =====================================================
  // 4️⃣ Absoluter Fallback
  // =====================================================
  if (!card) {
    const { rows: anyCard } = await db.execute({
      sql: `
        SELECT *
        FROM cards
        WHERE stack_id = ?
        ORDER BY RANDOM()
        LIMIT 1
      `,
      args: [stackId],
    });

    card = anyCard[0] || null;
  }

  res.json(card);
});


app.post(
  "/api/stacks/:stackId/cards/:cardId/review",
  requireAuth,
  async (req, res) => {
    const { cardId, stackId } = req.params;
    const { rating } = req.body || {};

    const { rows: stackRows } = await db.execute(
      "SELECT user_id FROM stacks WHERE id = ?",
      [stackId]
    );
    if (stackRows.length === 0)
      return res.status(404).json({ error: "Stack not found" });
    if (stackRows[0].user_id !== req.user.id)
      return res.status(403).json({ error: "Forbidden" });

    const { rows } = await db.execute({
      sql: `SELECT * FROM cards WHERE id=?`,
      args: [cardId],
    });
    const card = rows[0];
    if (!card) return res.status(404).json({ error: "card not found" });

    const oldBox = card.box;
    let nextBox = card.box;
    let nextDue = new Date();

    switch (rating) {
      case "hard":
        nextBox = Math.max(1, card.box - 1);
        nextDue.setDate(nextDue.getDate() + boxIntervals[nextBox]);
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

    // ✅ NEU: Session Counter holen/erhöhen
    const sessionKey = `study_session_${req.user.id}_${stackId}`;
    if (!global.studySessions) global.studySessions = {};
    if (!global.studySessions[sessionKey]) {
      global.studySessions[sessionKey] = { counter: 0, startTime: Date.now() };
    }
    
    // Counter ERHÖHEN (vor der Berechnung!)
    global.studySessions[sessionKey].counter++;
    const absoluteCounter = global.studySessions[sessionKey].counter;
    
    // ✅ FIXED: review_sequence basiert jetzt auf absolutem Counter
    let newReviewSeq;
    if (rating === "hard") {
      // Für "hard": 7-10 Karten Verzögerung (größerer Abstand)
      const cardsDelay = Math.floor(Math.random() * 4) + 7;
      newReviewSeq = absoluteCounter + cardsDelay;
    } else {
      // Für "good" und "easy": Kleine Verzögerung (1-2 Karten)
      // Verhindert sofortige Wiederholung auch bei "good"
      newReviewSeq = absoluteCounter + Math.floor(Math.random() * 2) + 1;
    }

    // Update card statistics
    const ratingColumn = `${rating}_count`;
    await db.execute({
      sql: `UPDATE cards 
            SET box=?, 
                due_at=?, 
                review_count = review_count + 1,
                review_sequence = ?,
                ${ratingColumn} = ${ratingColumn} + 1,
                last_reviewed_at = ?,
                updated_at=? 
            WHERE id=?`,
      args: [nextBox, iso, newReviewSeq, now, now, cardId],
    });

    // Record review in history
    const reviewId = nanoid();
    await db.execute({
      sql: `INSERT INTO card_reviews (id, card_id, stack_id, user_id, rating, old_box, new_box, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [reviewId, cardId, stackId, req.user.id, rating, oldBox, nextBox, now],
    });

    const { rows: updatedRows } = await db.execute({
      sql: `SELECT * FROM cards WHERE id=?`,
      args: [cardId],
    });
    res.json(updatedRows[0]);
  }
);

// Einzelne Karte per ID abrufen
app.get("/api/cards/:id", optionalAuth, async (req, res) => {
  const { id } = req.params;

  const { rows } = await db.execute("SELECT * FROM cards WHERE id=?", [id]);
  const card = rows[0];
  if (!card) return res.status(404).json({ error: "card not found" });

  const { rows: stackRows } = await db.execute(
    "SELECT * FROM stacks WHERE id=?",
    [card.stack_id]
  );
  const stack = stackRows[0];
  
  if (!stack || !stack.is_public) {
    if (!req.user) {
      return res.status(403).json({ error: "Forbidden - Login required" });
    }
    if (stack && req.user.id !== stack.user_id) {
      const { rows: collaboratorRows } = await db.execute(
        "SELECT 1 FROM stack_collaborators WHERE stack_id = ? AND user_id = ?",
        [card.stack_id, req.user.id]
      );
      if (collaboratorRows.length === 0) {
        return res.status(403).json({ error: "forbidden" });
      }
    }
  }
  res.json(card);
});

// Karte aktualisieren
app.patch("/api/cards/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { front, back, front_image } = req.body || {};

  const { rows: cardRows } = await db.execute(
    "SELECT stack_id FROM cards WHERE id=?",
    [id]
  );
  if (cardRows.length === 0)
    return res.status(404).json({ error: "card not found" });
  const stack_id = cardRows[0].stack_id;

  const { rows: stacks } = await db.execute("SELECT * FROM stacks WHERE id=?", [
    stack_id,
  ]);
  const stack = stacks[0];
  if (!stack) return res.status(404).json({ error: "stack not found" });

  if (stack.user_id !== req.user.id) {
    const { rows: collaboratorRows } = await db.execute(
      "SELECT 1 FROM stack_collaborators WHERE stack_id = ? AND user_id = ?",
      [stack_id, req.user.id]
    );
    if (collaboratorRows.length === 0) {
      return res.status(403).json({ error: "Forbidden" });
    }
  }

  const updates = {};
  if (front !== undefined) updates.front = front.trim();
  if (back !== undefined) updates.back = back.trim();
  if (front_image !== undefined) {
    updates.front_image = front_image && front_image.trim() ? front_image.trim() : null;
  }

  if (Object.keys(updates).length === 0) {
    const { rows } = await db.execute("SELECT * FROM cards WHERE id=?", [id]);
    if (!rows.length) return res.status(404).json({ error: "not found" });
    return res.json(rows[0]);
  }

  const now = new Date().toISOString();
  updates.updated_at = now;

  const setClauses = Object.keys(updates).map((key) => `${key} = ?`);
  const args = [...Object.values(updates), id];

  await db.execute({
    sql: `UPDATE cards SET ${setClauses.join(", ")} WHERE id = ?`,
    args,
  });

  const { rows } = await db.execute("SELECT * FROM cards WHERE id=?", [id]);
  if (!rows.length) return res.status(404).json({ error: "not found" });

  res.json(rows[0]);
});

// Karte löschen
app.delete("/api/cards/:id", requireAuth, async (req, res) => {
  const { id } = req.params;

  const { rows: cardRows } = await db.execute(
    "SELECT stack_id FROM cards WHERE id=?",
    [id]
  );
  if (cardRows.length === 0)
    return res.status(404).json({ error: "card not found" });
  const stack_id = cardRows[0].stack_id;

  const { rows: stacks } = await db.execute("SELECT * FROM stacks WHERE id=?", [
    stack_id,
  ]);
  const stack = stacks[0];
  if (!stack) return res.status(404).json({ error: "stack not found" });

  if (stack.user_id !== req.user.id) {
    const { rows: collaboratorRows } = await db.execute(
      "SELECT 1 FROM stack_collaborators WHERE stack_id = ? AND user_id = ?",
      [stack_id, req.user.id]
    );
    if (collaboratorRows.length === 0) {
      return res.status(403).json({ error: "Forbidden" });
    }
  }

  await db.execute({
    sql: `DELETE FROM cards WHERE id=?`,
    args: [id],
  });

  res.status(204).end();
});

/* ========== SCRIBBLEPAD ========== */

app.get("/api/scribblepad", requireAuth, async (req, res) => {
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

app.post("/api/scribblepad", requireAuth, async (req, res) => {
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

/* ========== FRIENDS ========== */

app.get("/api/friends", requireAuth, async (req, res) => {
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

app.get("/api/friends/requests/sent", requireAuth, async (req, res) => {
  const userId = req.user.id;
  const { rows } = await db.execute({
    sql: `
      SELECT fr.id, fr.receiver_id, u.username AS name
      FROM friend_requests fr
      JOIN users u ON u.id = fr.receiver_id
      WHERE fr.sender_id = ?
    `,
    args: [userId],
  });
  res.json(rows);
});

app.get("/api/friends/requests", requireAuth, async (req, res) => {
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

app.post("/api/friends/requests", requireAuth, async (req, res) => {
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
  console.log("Friend requests rows:", rows);
  res.status(201).json({ success: true });
});

app.put("/api/friends/requests/:senderId", requireAuth, async (req, res) => {
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

app.delete("/api/friends/requests/:senderId", requireAuth, async (req, res) => {
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

app.delete("/api/friends/:friendId", requireAuth, async (req, res) => {
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

/* ========== USERS ========== */

app.get("/api/users/:id", async (req, res) => {
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

/* ========== USER STATISTICS ========== */
app.get("/api/users/:userId/statistics", optionalAuth, async (req, res) => {
  const { userId } = req.params;

  // Check if viewing own profile or if profile is public
  const isOwnProfile = req.user && req.user.id === parseInt(userId);
  
  // Get user's public stacks to determine if any info should be public
  const { rows: userStacks } = await db.execute({
    sql: "SELECT COUNT(*) as public_count FROM stacks WHERE user_id = ? AND is_public = 1",
    args: [userId]
  });

  // Build WHERE clause based on access
  // ✅ NEW: Always include all stacks (public + private), but we'll hide names later
  const stackFilter = "s.user_id = ?";

  // Overall Statistics
  const { rows: overallStats } = await db.execute({
    sql: `
      SELECT 
        COUNT(DISTINCT s.id) as total_stacks,
        COUNT(DISTINCT c.id) as total_cards,
        COALESCE(SUM(c.review_count), 0) as total_reviews,
        COALESCE(AVG(c.box), 0) as average_box,
        COALESCE(SUM(c.again_count), 0) as total_again,
        COALESCE(SUM(c.hard_count), 0) as total_hard,
        COALESCE(SUM(c.good_count), 0) as total_good,
        COALESCE(SUM(c.easy_count), 0) as total_easy
      FROM stacks s
      LEFT JOIN cards c ON c.stack_id = s.id
      WHERE ${stackFilter}
    `,
    args: [userId]
  });

  // Calculate accuracy
  const stats = overallStats[0];
  const totalResponses = stats.total_again + stats.total_hard + stats.total_good + stats.total_easy;
  const correctResponses = stats.total_good + stats.total_easy;
  stats.average_accuracy = totalResponses > 0 
    ? Math.round((correctResponses / totalResponses) * 100) 
    : 0;

  // Stack Performance (Top 5 best performing stacks)
  const { rows: topStacks } = await db.execute({
    sql: `
      SELECT 
        s.id,
        s.name,
        s.is_public,
        COUNT(c.id) as card_count,
        COALESCE(AVG(c.box), 0) as average_box,
        COALESCE(SUM(c.review_count), 0) as total_reviews
      FROM stacks s
      LEFT JOIN cards c ON c.stack_id = s.id
      WHERE ${stackFilter}
      GROUP BY s.id
      HAVING card_count > 0
      ORDER BY average_box DESC, total_reviews DESC
      LIMIT 5
    `,
    args: [userId]
  });

  // Most Reviewed Stacks
  const { rows: mostReviewedStacks } = await db.execute({
    sql: `
      SELECT 
        s.id,
        s.name,
        s.is_public,
        COUNT(c.id) as card_count,
        COALESCE(SUM(c.review_count), 0) as total_reviews
      FROM stacks s
      LEFT JOIN cards c ON c.stack_id = s.id
      WHERE ${stackFilter}
      GROUP BY s.id
      HAVING total_reviews > 0
      ORDER BY total_reviews DESC
      LIMIT 5
    `,
    args: [userId]
  });

  // ✅ NEW: Hide names of private stacks if not own profile
  const anonymizeStack = (stack) => {
    if (!isOwnProfile && !stack.is_public) {
      return {
        ...stack,
        name: 'Private Stack',
        is_anonymous: true
      };
    }
    return {
      ...stack,
      is_anonymous: false
    };
  };

  // Study Streak (only for own profile)
  let studyStreak = { current_streak: 0, longest_streak: 0, last_study_date: null };
  if (isOwnProfile) {
    const { rows: recentReviews } = await db.execute({
      sql: `
        SELECT DISTINCT DATE(created_at) as study_date
        FROM card_reviews
        WHERE user_id = ?
        ORDER BY study_date DESC
        LIMIT 365
      `,
      args: [userId]
    });

    if (recentReviews.length > 0) {
      // Calculate current streak
      let currentStreak = 0;
      let longestStreak = 0;
      let tempStreak = 0;
      const today = new Date();
      today.setHours(0, 0, 0, 0);

      for (let i = 0; i < recentReviews.length; i++) {
        const studyDate = new Date(recentReviews[i].study_date);
        studyDate.setHours(0, 0, 0, 0);
        
        const expectedDate = new Date(today);
        expectedDate.setDate(today.getDate() - i);
        expectedDate.setHours(0, 0, 0, 0);

        if (studyDate.getTime() === expectedDate.getTime()) {
          currentStreak++;
          tempStreak++;
          longestStreak = Math.max(longestStreak, tempStreak);
        } else {
          if (i === 0) currentStreak = 0;
          tempStreak = 1;
          longestStreak = Math.max(longestStreak, tempStreak);
        }
      }

      studyStreak = {
        current_streak: currentStreak,
        longest_streak: longestStreak,
        last_study_date: recentReviews[0].study_date
      };
    }
  }

  // Recent Activity (last 30 days)
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const { rows: recentActivity } = await db.execute({
    sql: `
      SELECT 
        DATE(cr.created_at) as date,
        COUNT(*) as review_count,
        SUM(CASE WHEN cr.rating = 'again' THEN 1 ELSE 0 END) as again_count,
        SUM(CASE WHEN cr.rating = 'hard' THEN 1 ELSE 0 END) as hard_count,
        SUM(CASE WHEN cr.rating = 'good' THEN 1 ELSE 0 END) as good_count,
        SUM(CASE WHEN cr.rating = 'easy' THEN 1 ELSE 0 END) as easy_count
      FROM card_reviews cr
      JOIN stacks s ON cr.stack_id = s.id
      WHERE ${stackFilter} AND cr.created_at >= ?
      GROUP BY DATE(cr.created_at)
      ORDER BY date DESC
    `,
    args: [userId, thirtyDaysAgo]
  });

  // Box Distribution (across all user's cards)
  const { rows: boxDistribution } = await db.execute({
    sql: `
      SELECT 
        c.box,
        COUNT(*) as count
      FROM cards c
      JOIN stacks s ON c.stack_id = s.id
      WHERE ${stackFilter}
      GROUP BY c.box
      ORDER BY c.box
    `,
    args: [userId]
  });

  // Weekly Review Stats (for chart)
  const { rows: weeklyStats } = await db.execute({
    sql: `
      SELECT 
        strftime('%w', cr.created_at) as day_of_week,
        COUNT(*) as review_count
      FROM card_reviews cr
      JOIN stacks s ON cr.stack_id = s.id
      WHERE ${stackFilter} AND cr.created_at >= datetime('now', '-30 days')
      GROUP BY day_of_week
      ORDER BY day_of_week
    `,
    args: [userId]
  });

  res.json({
    overall: stats,
    topStacks: topStacks.map(anonymizeStack),
    mostReviewedStacks: mostReviewedStacks.map(anonymizeStack),
    studyStreak: isOwnProfile ? studyStreak : null,
    recentActivity,
    boxDistribution,
    weeklyStats,
    limited: false
  });
});

/* ========== ADMIN MIDDLEWARE ========== */

const requireAdmin = async (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: "Authentication required" });
  }

  // Check if user is admin (Luca or McLearn)
  const { rows } = await db.execute({
    sql: "SELECT username FROM users WHERE id = ?",
    args: [req.user.id],
  });

  if (rows.length === 0) {
    return res.status(401).json({ error: "User not found" });
  }

  const username = rows[0].username;
  if (username !== "Luca" && username !== "McLearn") {
    return res.status(403).json({ error: "Admin access required" });
  }

  next();
};

/* ========== ADMIN ENDPOINTS ========== */

// Get all users
app.get("/api/admin/users", requireAuth, requireAdmin, async (req, res) => {
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
app.get("/api/admin/stacks", requireAuth, requireAdmin, async (req, res) => {
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

// Delete user (admin only)
app.delete("/api/admin/users/:userId", requireAuth, requireAdmin, async (req, res) => {
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

// Delete stack (admin only)
app.delete("/api/admin/stacks/:stackId", requireAuth, requireAdmin, async (req, res) => {
  const { stackId } = req.params;
  try {
    await db.execute({
      sql: "DELETE FROM stacks WHERE id = ?",
      args: [stackId],
    });
    res.status(204).end();
  } catch (err) {
    console.error("Error deleting stack (admin):", err);
    res.status(500).json({ error: "Failed to delete stack: " + err.message });
  }
});

// Update stack visibility (admin only)
app.patch("/api/admin/stacks/:stackId", requireAuth, requireAdmin, async (req, res) => {
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

// Transfer stack ownership (admin only)
app.patch("/api/admin/stacks/:stackId/transfer", requireAuth, requireAdmin, async (req, res) => {
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
app.get("/api/admin/statistics", requireAuth, requireAdmin, async (req, res) => {
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

// ============================================
// ADMIN: Reset Review Sequences Endpoint
// Füge das zu deinen Admin Endpoints hinzu (nach den anderen admin endpoints)
// ============================================

// Reset review sequences for a stack (admin only)
app.post("/api/admin/stacks/:stackId/reset-sequences", requireAuth, requireAdmin, async (req, res) => {
  const { stackId } = req.params;

  try {
    // Check if stack exists
    const { rows: stackRows } = await db.execute({
      sql: "SELECT id, name FROM stacks WHERE id = ?",
      args: [stackId],
    });

    if (stackRows.length === 0) {
      return res.status(404).json({ error: "Stack not found" });
    }

    const stack = stackRows[0];

    // Reset all review_sequence values for this stack
    await db.execute({
      sql: "UPDATE cards SET review_sequence = NULL WHERE stack_id = ?",
      args: [stackId],
    });

    // Count how many cards were affected
    const { rows: countRows } = await db.execute({
      sql: "SELECT COUNT(*) as count FROM cards WHERE stack_id = ?",
      args: [stackId],
    });

    const affectedCards = countRows[0].count;

    console.log(`✅ Reset review sequences for ${affectedCards} cards in stack "${stack.name}"`);

    res.json({
      success: true,
      message: `Reset review sequences for ${affectedCards} cards`,
      stack_id: stackId,
      affected_cards: affectedCards
    });

  } catch (err) {
    console.error("Error resetting review sequences:", err);
    res.status(500).json({ error: "Failed to reset review sequences" });
  }
});

// ========================================
// MAINTENANCE MODE ENDPOINTS & MIDDLEWARE
// Füge dies NACH den Admin-Endpoints ein
// ========================================

/* ========== MAINTENANCE MODE ========== */

// GET: Maintenance Mode Status (öffentlich zugänglich)
app.get("/api/admin/maintenance-mode", async (req, res) => {
  try {
    const { rows } = await db.execute({
      sql: "SELECT maintenance_mode, updated_at, updated_by FROM app_settings WHERE id = 1",
      args: []
    });

    if (rows.length === 0) {
      // Falls kein Eintrag existiert, erstelle einen
      await db.execute({
        sql: "INSERT INTO app_settings (id, maintenance_mode) VALUES (1, 0)",
        args: []
      });
      
      return res.json({
        maintenance_mode: false,
        updated_at: null,
        updated_by: null
      });
    }

    const row = rows[0];
    res.json({
      maintenance_mode: row.maintenance_mode === 1,  // SQLite: 1 = true, 0 = false
      updated_at: row.updated_at,
      updated_by: row.updated_by
    });

  } catch (error) {
    console.error('Error fetching maintenance mode:', error);
    res.status(500).json({ error: 'Failed to fetch maintenance mode' });
  }
});

// POST: Maintenance Mode setzen (nur Admins)
app.post("/api/admin/maintenance-mode", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { maintenance_mode } = req.body;
    
    if (typeof maintenance_mode !== 'boolean') {
      return res.status(400).json({ 
        error: 'maintenance_mode must be a boolean' 
      });
    }

    const now = new Date().toISOString();
    const username = req.user.username;

    // Update in Datenbank
    await db.execute({
      sql: `
        INSERT INTO app_settings (id, maintenance_mode, updated_at, updated_by)
        VALUES (1, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          maintenance_mode = ?,
          updated_at = ?,
          updated_by = ?
      `,
      args: [
        maintenance_mode ? 1 : 0,
        now,
        username,
        maintenance_mode ? 1 : 0,
        now,
        username
      ]
    });

    console.log(`✅ Maintenance mode ${maintenance_mode ? 'ACTIVATED' : 'DEACTIVATED'} by ${username}`);

    res.json({
      maintenance_mode,
      updated_at: now,
      updated_by: username
    });

  } catch (error) {
    console.error('Error setting maintenance mode:', error);
    res.status(500).json({ error: 'Failed to set maintenance mode' });
  }
});

/* ========== MAINTENANCE MODE MIDDLEWARE ========== */
// WICHTIG: Diese Middleware NACH requireAuth und requireAdmin Definitionen,
// aber VOR den anderen Routes einfügen!

// Cache für Maintenance Mode Status (Performance-Optimierung)
let maintenanceModeCache = {
  isActive: false,
  lastChecked: 0
};

const CACHE_DURATION = 10000; // 10 Sekunden Cache

// Hilfsfunktion: Prüfe ob User Admin ist
function isAdmin(username) {
  return username === 'Luca' || username === 'McLearn';
}

// Middleware: Prüft Maintenance Mode und blockt nicht-Admin User
async function maintenanceModeMiddleware(req, res, next) {
  try {
    // Liste der erlaubten Routen (immer zugänglich)
    const allowedPaths = [
      '/api/login',
      '/api/register',
      '/api/admin/maintenance-mode',
      '/api/health'
    ];

    // Prüfe ob Route erlaubt ist
    if (allowedPaths.some(path => req.path.startsWith(path))) {
      return next();
    }

    // Prüfe Cache
    const now = Date.now();
    if (now - maintenanceModeCache.lastChecked < CACHE_DURATION) {
      if (!maintenanceModeCache.isActive) {
        return next();
      }
      // Wenn Cache sagt aktiv, prüfe ob User Admin ist
      if (req.user && isAdmin(req.user.username)) {
        return next();
      }
      return res.status(503).json({
        error: 'Service temporarily unavailable',
        message: 'Maintenance mode is active. Please try again later.'
      });
    }

    // Lade Status aus Datenbank
    const { rows } = await db.execute({
      sql: 'SELECT maintenance_mode FROM app_settings WHERE id = 1',
      args: []
    });

    // Update Cache
    maintenanceModeCache = {
      isActive: rows[0]?.maintenance_mode === 1,
      lastChecked: now
    };

    // Maintenance Mode nicht aktiv -> durchlassen
    if (!maintenanceModeCache.isActive) {
      return next();
    }

    // Maintenance Mode aktiv -> prüfe ob User Admin ist
    if (req.user && isAdmin(req.user.username)) {
      return next();
    }

    // Nicht-Admin User blocken
    return res.status(503).json({
      error: 'Service temporarily unavailable',
      message: 'Maintenance mode is active. Please try again later.'
    });

  } catch (error) {
    console.error('Error in maintenance mode middleware:', error);
    // Bei Fehler durchlassen (Fail-Open Strategie)
    next();
  }
}

// ========================================
// GET: Alle Questions eines Stacks
// ========================================
app.get("/api/stacks/:stackId/questions", optionalAuth, async (req, res) => {
  const { stackId } = req.params;

  // Check if stack exists and is accessible
  const { rows: stackRows } = await db.execute(
    "SELECT * FROM stacks WHERE id = ?",
    [stackId]
  );
  const stack = stackRows[0];
  if (!stack) return res.status(404).json({ error: "Stack not found" });

  // Access control
  if (!stack.is_public) {
    if (!req.user) {
      return res.status(403).json({ error: "Forbidden - Login required" });
    }
    if (stack.user_id !== req.user.id) {
      const { rows: collaboratorRows } = await db.execute(
        "SELECT 1 FROM stack_collaborators WHERE stack_id = ? AND user_id = ?",
        [stackId, req.user.id]
      );
      if (collaboratorRows.length === 0) {
        return res.status(403).json({ error: "Forbidden" });
      }
    }
  }

  // Get all questions for this stack
  const { rows } = await db.execute({
    sql: `SELECT * FROM questions WHERE stack_id = ? ORDER BY created_at ASC`,
    args: [stackId],
  });

  res.json(rows);
});

// ========================================
// POST: Create a new Question
// ========================================
app.post("/api/stacks/:stackId/questions", requireAuth, async (req, res) => {
  const { stackId } = req.params;
  const { question, answer_1, answer_2, answer_3, answer_4, correct_answer, explanation, difficulty } = req.body || {};

  // Validation
  if (!question?.trim() || !answer_1?.trim() || !answer_2?.trim() || !answer_3?.trim() || !answer_4?.trim()) {
    return res.status(400).json({ error: "Question and all 4 answers are required" });
  }

  if (!correct_answer || correct_answer < 1 || correct_answer > 4) {
    return res.status(400).json({ error: "correct_answer must be between 1 and 4" });
  }

  // Check if stack exists and user has permission
  const { rows: stackRows } = await db.execute(
    "SELECT * FROM stacks WHERE id = ?",
    [stackId]
  );
  const stack = stackRows[0];
  if (!stack) return res.status(404).json({ error: "Stack not found" });

  if (stack.user_id !== req.user.id) {
    const { rows: collaboratorRows } = await db.execute(
      "SELECT 1 FROM stack_collaborators WHERE stack_id = ? AND user_id = ?",
      [stackId, req.user.id]
    );
    if (collaboratorRows.length === 0) {
      return res.status(403).json({ error: "Forbidden" });
    }
  }

  // Create question
  const id = nanoid();
  const now = new Date().toISOString();

  await db.execute({
    sql: `INSERT INTO questions (
      id, stack_id, question, answer_1, answer_2, answer_3, answer_4, 
      correct_answer, explanation, difficulty, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [
      id, stackId, question.trim(), answer_1.trim(), answer_2.trim(), 
      answer_3.trim(), answer_4.trim(), correct_answer, 
      explanation?.trim() || null, difficulty || null, now, now
    ],
  });

  const { rows } = await db.execute("SELECT * FROM questions WHERE id = ?", [id]);
  res.status(201).json(rows[0]);
});

// ========================================
// PATCH: Update a Question
// ========================================
app.patch("/api/questions/:questionId", requireAuth, async (req, res) => {
  const { questionId } = req.params;
  const { question, answer_1, answer_2, answer_3, answer_4, correct_answer, explanation, difficulty } = req.body || {};

  // Get question to check stack ownership
  const { rows: questionRows } = await db.execute(
    "SELECT stack_id FROM questions WHERE id = ?",
    [questionId]
  );
  if (questionRows.length === 0) {
    return res.status(404).json({ error: "Question not found" });
  }

  const stack_id = questionRows[0].stack_id;

  // Check permission
  const { rows: stackRows } = await db.execute(
    "SELECT * FROM stacks WHERE id = ?",
    [stack_id]
  );
  const stack = stackRows[0];
  if (!stack) return res.status(404).json({ error: "Stack not found" });

  if (stack.user_id !== req.user.id) {
    const { rows: collaboratorRows } = await db.execute(
      "SELECT 1 FROM stack_collaborators WHERE stack_id = ? AND user_id = ?",
      [stack_id, req.user.id]
    );
    if (collaboratorRows.length === 0) {
      return res.status(403).json({ error: "Forbidden" });
    }
  }

  // Build update query
  const updates = {};
  if (question !== undefined) updates.question = question.trim();
  if (answer_1 !== undefined) updates.answer_1 = answer_1.trim();
  if (answer_2 !== undefined) updates.answer_2 = answer_2.trim();
  if (answer_3 !== undefined) updates.answer_3 = answer_3.trim();
  if (answer_4 !== undefined) updates.answer_4 = answer_4.trim();
  if (correct_answer !== undefined) {
    if (correct_answer < 1 || correct_answer > 4) {
      return res.status(400).json({ error: "correct_answer must be between 1 and 4" });
    }
    updates.correct_answer = correct_answer;
  }
  if (explanation !== undefined) updates.explanation = explanation?.trim() || null;
  if (difficulty !== undefined) updates.difficulty = difficulty || null;

  if (Object.keys(updates).length === 0) {
    const { rows } = await db.execute("SELECT * FROM questions WHERE id = ?", [questionId]);
    return res.json(rows[0]);
  }

  const now = new Date().toISOString();
  updates.updated_at = now;

  const setClauses = Object.keys(updates).map((key) => `${key} = ?`);
  const args = [...Object.values(updates), questionId];

  await db.execute({
    sql: `UPDATE questions SET ${setClauses.join(", ")} WHERE id = ?`,
    args,
  });

  const { rows } = await db.execute("SELECT * FROM questions WHERE id = ?", [questionId]);
  res.json(rows[0]);
});

// ========================================
// DELETE: Delete a Question
// ========================================
app.delete("/api/questions/:questionId", requireAuth, async (req, res) => {
  const { questionId } = req.params;

  // Get question to check stack ownership
  const { rows: questionRows } = await db.execute(
    "SELECT stack_id FROM questions WHERE id = ?",
    [questionId]
  );
  if (questionRows.length === 0) {
    return res.status(404).json({ error: "Question not found" });
  }

  const stack_id = questionRows[0].stack_id;

  // Check permission
  const { rows: stackRows } = await db.execute(
    "SELECT * FROM stacks WHERE id = ?",
    [stack_id]
  );
  const stack = stackRows[0];
  if (!stack) return res.status(404).json({ error: "Stack not found" });

  if (stack.user_id !== req.user.id) {
    const { rows: collaboratorRows } = await db.execute(
      "SELECT 1 FROM stack_collaborators WHERE stack_id = ? AND user_id = ?",
      [stack_id, req.user.id]
    );
    if (collaboratorRows.length === 0) {
      return res.status(403).json({ error: "Forbidden" });
    }
  }

  // Delete question (cascade will delete results)
  await db.execute({
    sql: "DELETE FROM questions WHERE id = ?",
    args: [questionId],
  });

  res.status(204).end();
});

// ========================================
// POST: Submit Question Answer & Record Result
// ========================================
app.post("/api/questions/:questionId/answer", requireAuth, async (req, res) => {
  const { questionId } = req.params;
  const { selected_answer, time_taken } = req.body || {};

  if (!selected_answer || selected_answer < 1 || selected_answer > 4) {
    return res.status(400).json({ error: "selected_answer must be between 1 and 4" });
  }

  // Get question
  const { rows: questionRows } = await db.execute(
    "SELECT * FROM questions WHERE id = ?",
    [questionId]
  );
  if (questionRows.length === 0) {
    return res.status(404).json({ error: "Question not found" });
  }

  const question = questionRows[0];
  const is_correct = selected_answer === question.correct_answer ? 1 : 0;

  // Record result
  const id = nanoid();
  const now = new Date().toISOString();

  await db.execute({
    sql: `INSERT INTO question_results (
      id, question_id, stack_id, user_id, selected_answer, 
      is_correct, time_taken, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [
      id, questionId, question.stack_id, req.user.id, 
      selected_answer, is_correct, time_taken || null, now
    ],
  });

  // Return result with correct answer info
  res.json({
    id,
    is_correct: is_correct === 1,
    correct_answer: question.correct_answer,
    explanation: question.explanation,
    selected_answer
  });
});

// ========================================
// GET: Question Statistics for a Stack
// ========================================
app.get("/api/stacks/:stackId/questions/statistics", optionalAuth, async (req, res) => {
  const { stackId } = req.params;

  // Check access
  const { rows: stackRows } = await db.execute(
    "SELECT * FROM stacks WHERE id = ?",
    [stackId]
  );
  const stack = stackRows[0];
  if (!stack) return res.status(404).json({ error: "Stack not found" });

  if (!stack.is_public) {
    if (!req.user) {
      return res.status(403).json({ error: "Forbidden - Login required" });
    }
    if (stack.user_id !== req.user.id) {
      const { rows: collaboratorRows } = await db.execute(
        "SELECT 1 FROM stack_collaborators WHERE stack_id = ? AND user_id = ?",
        [stackId, req.user.id]
      );
      if (collaboratorRows.length === 0) {
        return res.status(403).json({ error: "Forbidden" });
      }
    }
  }

  // Overall statistics
  const { rows: overallStats } = await db.execute({
    sql: `
      SELECT 
        COUNT(DISTINCT q.id) as total_questions,
        COUNT(qr.id) as total_attempts,
        SUM(CASE WHEN qr.is_correct = 1 THEN 1 ELSE 0 END) as correct_answers,
        AVG(CASE WHEN qr.time_taken IS NOT NULL THEN qr.time_taken END) as avg_time_taken
      FROM questions q
      LEFT JOIN question_results qr ON q.id = qr.question_id
      WHERE q.stack_id = ?
    `,
    args: [stackId],
  });

  // User-specific stats (if logged in)
  let userStats = null;
  if (req.user) {
    const { rows: userStatsRows } = await db.execute({
      sql: `
        SELECT 
          COUNT(DISTINCT question_id) as attempted_questions,
          COUNT(*) as total_attempts,
          SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END) as correct_answers,
          AVG(CASE WHEN time_taken IS NOT NULL THEN time_taken END) as avg_time_taken
        FROM question_results
        WHERE stack_id = ? AND user_id = ?
      `,
      args: [stackId, req.user.id],
    });
    userStats = userStatsRows[0];
  }

  // Most difficult questions (lowest correct rate)
  const { rows: difficultQuestions } = await db.execute({
    sql: `
      SELECT 
        q.id,
        q.question,
        COUNT(qr.id) as attempt_count,
        SUM(CASE WHEN qr.is_correct = 1 THEN 1 ELSE 0 END) as correct_count,
        ROUND(AVG(qr.is_correct) * 100, 2) as correct_percentage
      FROM questions q
      LEFT JOIN question_results qr ON q.id = qr.question_id
      WHERE q.stack_id = ?
      GROUP BY q.id
      HAVING attempt_count > 0
      ORDER BY correct_percentage ASC, attempt_count DESC
      LIMIT 5
    `,
    args: [stackId],
  });

  res.json({
    overall: overallStats[0],
    user: userStats,
    difficult_questions: difficultQuestions
  });
});

// ========================================
// POST: Bulk Import Questions from CSV
// ========================================
app.post("/api/stacks/:stackId/questions/import", requireAuth, async (req, res) => {
  const { stackId } = req.params;
  const { questions } = req.body || {};

  if (!Array.isArray(questions) || questions.length === 0) {
    return res.status(400).json({ error: "questions array is required" });
  }

  // Check permission
  const { rows: stackRows } = await db.execute(
    "SELECT * FROM stacks WHERE id = ?",
    [stackId]
  );
  const stack = stackRows[0];
  if (!stack) return res.status(404).json({ error: "Stack not found" });

  if (stack.user_id !== req.user.id) {
    const { rows: collaboratorRows } = await db.execute(
      "SELECT 1 FROM stack_collaborators WHERE stack_id = ? AND user_id = ?",
      [stackId, req.user.id]
    );
    if (collaboratorRows.length === 0) {
      return res.status(403).json({ error: "Forbidden" });
    }
  }

  const now = new Date().toISOString();
  const imported = [];
  const errors = [];

  // Import each question
  for (let i = 0; i < questions.length; i++) {
    const q = questions[i];
    
    try {
      // Validate
      if (!q.question?.trim() || !q.answer_1?.trim() || !q.answer_2?.trim() || 
          !q.answer_3?.trim() || !q.answer_4?.trim()) {
        errors.push({ index: i, error: "Missing required fields" });
        continue;
      }

      if (!q.correct_answer || q.correct_answer < 1 || q.correct_answer > 4) {
        errors.push({ index: i, error: "correct_answer must be between 1 and 4" });
        continue;
      }

      const id = nanoid();
      
      await db.execute({
        sql: `INSERT INTO questions (
          id, stack_id, question, answer_1, answer_2, answer_3, answer_4, 
          correct_answer, explanation, difficulty, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [
          id, stackId, q.question.trim(), q.answer_1.trim(), q.answer_2.trim(), 
          q.answer_3.trim(), q.answer_4.trim(), q.correct_answer, 
          q.explanation?.trim() || null, q.difficulty || null, now, now
        ],
      });

      imported.push({ index: i, id });
    } catch (err) {
      errors.push({ index: i, error: err.message });
    }
  }

  res.json({
    success: true,
    imported: imported.length,
    errors: errors.length,
    details: { imported, errors }
  });
});

/* ========== SCRIBBLEPAD - FINAL FIX ========== */

app.get("/api/scribblepad", requireAuth, async (req, res) => {
  const userId = req.user.id;

  try {
    const { rows } = await db.execute({
      sql: "SELECT * FROM scribblepad WHERE user_id = ?",
      args: [userId],
    });

    if (rows.length === 0) {
      return res.status(404).json({ error: "ScribblePad not found" });
    }

    // Ensure content is never null
    const pad = rows[0];
    pad.content = pad.content || '';
    
    res.json(pad);
  } catch (err) {
    console.error("Error fetching scribblepad:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/scribblepad", requireAuth, async (req, res) => {
  const userId = req.user.id;
  let { content, image } = req.body;

  // WICHTIG: Ensure content is always a string, never null/undefined
  content = (content !== null && content !== undefined) ? String(content) : '';
  
  // WICHTIG: Ensure image is either string or null
  image = (image !== null && image !== undefined && image !== '') ? String(image) : null;

  console.log('📝 ScribblePad Save Request:', {
    userId,
    contentType: typeof content,
    contentLength: content.length,
    contentPreview: content.substring(0, 50) + '...',
    imageType: typeof image,
    hasImage: !!image,
    imageLength: image?.length || 0
  });

  // Validate image size
  if (image && image.length > 7000000) {
    console.error('❌ Image too large:', image.length);
    return res.status(400).json({ error: "Image size too large (max 5MB)" });
  }

  try {
    const now = new Date().toISOString();

    // Check if scribblepad exists for this user
    const { rows: existing } = await db.execute({
      sql: "SELECT id FROM scribblepad WHERE user_id = ?",
      args: [userId],
    });

    if (existing.length > 0) {
      // UPDATE existing scribblepad
      console.log('🔄 Updating scribblepad for user:', userId);
      
      const result = await db.execute({
        sql: "UPDATE scribblepad SET content = ?, image = ?, updated_at = ? WHERE user_id = ?",
        args: [content, image, now, userId],
      });

      console.log('Update result:', result);

      // Fetch updated record to verify
      const { rows: updated } = await db.execute({
        sql: "SELECT * FROM scribblepad WHERE user_id = ?",
        args: [userId],
      });

      const savedPad = updated[0];
      console.log('✅ ScribblePad updated:', {
        id: savedPad.id,
        contentLength: savedPad.content?.length || 0,
        hasImage: !!savedPad.image
      });

      // Ensure content is never null in response
      savedPad.content = savedPad.content || '';
      
      res.json(savedPad);
      
    } else {
      // INSERT new scribblepad
      console.log('➕ Creating new scribblepad for user:', userId);
      
      const id = nanoid();
      
      const result = await db.execute({
        sql: `INSERT INTO scribblepad (id, user_id, content, image, created_at, updated_at)
              VALUES (?, ?, ?, ?, ?, ?)`,
        args: [id, userId, content, image, now, now],
      });

      console.log('Insert result:', result);

      // Fetch created record to verify
      const { rows: created } = await db.execute({
        sql: "SELECT * FROM scribblepad WHERE id = ?",
        args: [id],
      });

      const savedPad = created[0];
      console.log('✅ ScribblePad created:', {
        id: savedPad.id,
        contentLength: savedPad.content?.length || 0,
        hasImage: !!savedPad.image
      });

      // Ensure content is never null in response
      savedPad.content = savedPad.content || '';
      
      res.status(201).json(savedPad);
    }
  } catch (err) {
    console.error("❌ Error saving scribblepad:", err);
    console.error("Error details:", err.message);
    console.error("Stack trace:", err.stack);
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

/* ========== SCRIBBLEPAD - ULTRA DEBUG VERSION ========== */

app.post("/api/scribblepad", requireAuth, async (req, res) => {
  const userId = req.user.id;
  let { content, image } = req.body;

  console.log('=====================================');
  console.log('📝 SCRIBBLEPAD SAVE REQUEST');
  console.log('=====================================');
  console.log('User ID:', userId);
  console.log('Raw body keys:', Object.keys(req.body));
  console.log('Content type:', typeof content);
  console.log('Content value:', content?.substring(0, 50));
  console.log('Content length:', content?.length);
  console.log('Image type:', typeof image);
  console.log('Image is null?', image === null);
  console.log('Image is undefined?', image === undefined);
  console.log('Image length:', image?.length);
  console.log('Image preview:', image?.substring(0, 100));

  // Ensure content is always a string
  content = (content !== null && content !== undefined) ? String(content) : '';
  
  // Ensure image is either string or null
  image = (image !== null && image !== undefined && image !== '') ? String(image) : null;

  console.log('---AFTER PROCESSING---');
  console.log('Content (processed):', content.substring(0, 50));
  console.log('Image (processed):', image ? `STRING with ${image.length} chars` : 'NULL');

  if (image && image.length > 7000000) {
    console.error('❌ Image too large:', image.length);
    return res.status(400).json({ error: "Image size too large (max 5MB)" });
  }

  try {
    const now = new Date().toISOString();

    // Check if scribblepad exists
    const { rows: existing } = await db.execute({
      sql: "SELECT id FROM scribblepad WHERE user_id = ?",
      args: [userId],
    });

    console.log('Existing entries found:', existing.length);

    if (existing.length > 0) {
      // UPDATE
      console.log('🔄 UPDATING existing scribblepad');
      console.log('SQL:', "UPDATE scribblepad SET content = ?, image = ?, updated_at = ? WHERE user_id = ?");
      console.log('Args:', [
        `content: "${content.substring(0, 30)}..." (${content.length} chars)`,
        `image: ${image ? `STRING (${image.length} chars)` : 'NULL'}`,
        now,
        userId
      ]);

      const updateResult = await db.execute({
        sql: "UPDATE scribblepad SET content = ?, image = ?, updated_at = ? WHERE user_id = ?",
        args: [content, image, now, userId],
      });

      console.log('Update result:', updateResult);

      // VERIFY immediately after update
      const { rows: verify } = await db.execute({
        sql: "SELECT id, length(content) as content_len, length(image) as image_len, CASE WHEN image IS NULL THEN 'NULL' ELSE 'HAS_DATA' END as image_status FROM scribblepad WHERE user_id = ?",
        args: [userId],
      });

      console.log('🔍 VERIFICATION after UPDATE:', verify[0]);

      // Fetch full record
      const { rows: updated } = await db.execute({
        sql: "SELECT * FROM scribblepad WHERE user_id = ?",
        args: [userId],
      });

      const savedPad = updated[0];
      console.log('✅ Response data:', {
        id: savedPad.id,
        content_length: savedPad.content?.length || 0,
        image_length: savedPad.image?.length || 0,
        has_image: !!savedPad.image
      });

      savedPad.content = savedPad.content || '';
      
      console.log('=====================================');
      res.json(savedPad);
      
    } else {
      // INSERT
      console.log('➕ INSERTING new scribblepad');
      
      const id = nanoid();
      console.log('SQL:', "INSERT INTO scribblepad (id, user_id, content, image, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)");
      console.log('Args:', [
        id,
        userId,
        `content: "${content.substring(0, 30)}..." (${content.length} chars)`,
        `image: ${image ? `STRING (${image.length} chars)` : 'NULL'}`,
        now,
        now
      ]);

      const insertResult = await db.execute({
        sql: `INSERT INTO scribblepad (id, user_id, content, image, created_at, updated_at)
              VALUES (?, ?, ?, ?, ?, ?)`,
        args: [id, userId, content, image, now, now],
      });

      console.log('Insert result:', insertResult);

      // VERIFY immediately after insert
      const { rows: verify } = await db.execute({
        sql: "SELECT id, length(content) as content_len, length(image) as image_len, CASE WHEN image IS NULL THEN 'NULL' ELSE 'HAS_DATA' END as image_status FROM scribblepad WHERE id = ?",
        args: [id],
      });

      console.log('🔍 VERIFICATION after INSERT:', verify[0]);

      // Fetch full record
      const { rows: created } = await db.execute({
        sql: "SELECT * FROM scribblepad WHERE id = ?",
        args: [id],
      });

      const savedPad = created[0];
      console.log('✅ Response data:', {
        id: savedPad.id,
        content_length: savedPad.content?.length || 0,
        image_length: savedPad.image?.length || 0,
        has_image: !!savedPad.image
      });

      savedPad.content = savedPad.content || '';
      
      console.log('=====================================');
      res.status(201).json(savedPad);
    }
  } catch (err) {
    console.error("❌ ERROR saving scribblepad:");
    console.error("Message:", err.message);
    console.error("Stack:", err.stack);
    console.log('=====================================');
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// ========================================
// MIDDLEWARE INTEGRATION
// Füge diese Zeile NACH app.use(express.json()) 
// und NACH der optionalAuth Middleware ein:
// ========================================

// app.use(maintenanceModeMiddleware);


const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`✅ Yappy läuft auf http://localhost:${port}`);
});
