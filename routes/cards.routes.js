import { Router } from "express";
import { nanoid } from "nanoid";
import db from "../db.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { optionalAuth } from "../middleware/optionalAuth.js";
import { boxIntervals } from "../config/constants.js";

const router = Router();

// Get all cards for a stack
router.get("/", optionalAuth, async (req, res) => {
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

// Create card
router.post("/", requireAuth, async (req, res) => {
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

// Get single card
router.get("/:id", optionalAuth, async (req, res) => {
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

// Update card
router.patch("/:id", requireAuth, async (req, res) => {
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

// Delete card
router.delete("/:id", requireAuth, async (req, res) => {
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

// Get next card for study session
router.get("/stacks/:stackId/study/next", optionalAuth, async (req, res) => {
  const { stackId } = req.params;

  const { rows: stacks } = await db.execute("SELECT * FROM stacks WHERE id=?", [stackId]);
  const stack = stacks[0];
  if (!stack) {
    return res.status(404).json({ error: "stack not found" });
  }

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

  res.setHeader("Cache-Control", "no-store");

  const now = new Date().toISOString();
  let card;

  if (req.user && stack.user_id === req.user.id) {
    // Get current review count for this session
    const { rows: sessionCountRows } = await db.execute({
      sql: `SELECT COALESCE(MAX(review_sequence), 0) as current_seq FROM cards WHERE stack_id = ?`,
      args: [stackId]
    });
    const currentSeq = sessionCountRows[0].current_seq;

    // ✅ FIXED: Card-based cooldown system with proper prioritization
    
    // 1. Priority: Fällige Karten die ihr review_sequence erreicht haben
    const { rows: dueCards } = await db.execute({
      sql: `
        SELECT *, 
          (julianday('now') - julianday(due_at)) * 24 as hours_overdue,
          CASE 
            WHEN box = 1 THEN 10
            WHEN box = 2 THEN 8
            WHEN box = 3 THEN 6
            WHEN box = 4 THEN 4
            WHEN box = 5 THEN 2
            ELSE 1
          END as urgency_score,
          (hard_count * 3) as difficulty_score
        FROM cards
        WHERE stack_id = ?
          AND due_at <= ?
          AND (review_sequence IS NULL OR review_sequence <= ?)
        ORDER BY 
          urgency_score DESC,
          hours_overdue DESC,
          difficulty_score DESC,
          RANDOM()
        LIMIT 1
      `,
      args: [stackId, now, currentSeq],
    });

    if (dueCards.length > 0) {
      card = dueCards[0];
    }

    // 2. Fallback: Neue Karten (never reviewed)
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

    // 3. Fallback: Schwierigste Karten die bereit sind (Box 1-2)
    if (!card) {
      const { rows: hardCards } = await db.execute({
        sql: `
          SELECT *,
            (hard_count * 3) as difficulty_score
          FROM cards
          WHERE stack_id = ?
            AND box <= 2
            AND (review_sequence IS NULL OR review_sequence <= ?)
          ORDER BY 
            difficulty_score DESC,
            box ASC,
            RANDOM()
          LIMIT 1
        `,
        args: [stackId, currentSeq],
      });

      if (hardCards.length > 0) {
        card = hardCards[0];
      }
    }

    // 4. Fallback: Irgendeine Karte die bereit ist
    if (!card) {
      const { rows: anyCards } = await db.execute({
        sql: `
          SELECT *
          FROM cards
          WHERE stack_id = ?
            AND (review_sequence IS NULL OR review_sequence <= ?)
          ORDER BY 
            box ASC,
            review_count ASC,
            RANDOM()
          LIMIT 1
        `,
        args: [stackId, currentSeq],
      });

      card = anyCards[0];
    }

    // 5. ✅ NEW: If no cards available with current sequence, reset all sequences
    if (!card) {
      // Check if all cards are in cooldown
      const { rows: totalCards } = await db.execute({
        sql: `SELECT COUNT(*) as count FROM cards WHERE stack_id = ?`,
        args: [stackId]
      });
      
      if (totalCards[0].count > 0) {
        // Reset all review_sequence values to allow cards to be studied again
        await db.execute({
          sql: `UPDATE cards SET review_sequence = NULL WHERE stack_id = ?`,
          args: [stackId]
        });
        
        // Now try again to get a card
        const { rows: resetCards } = await db.execute({
          sql: `
            SELECT *, 
              CASE 
                WHEN box = 1 THEN 10
                WHEN box = 2 THEN 8
                WHEN box = 3 THEN 6
                WHEN box = 4 THEN 4
                WHEN box = 5 THEN 2
                ELSE 1
              END as urgency_score,
              (hard_count * 3) as difficulty_score
            FROM cards 
            WHERE stack_id = ? AND due_at <= ?
            ORDER BY urgency_score DESC, difficulty_score DESC, RANDOM()
            LIMIT 1
          `,
          args: [stackId, now]
        });
        
        if (resetCards.length > 0) {
          card = resetCards[0];
        }
      }
    }

    // 6. Absoluter Fallback: Komplett random (sollte nie erreicht werden)
    if (!card) {
      const { rows: randomCards } = await db.execute({
        sql: `SELECT * FROM cards WHERE stack_id = ? ORDER BY RANDOM() LIMIT 1`,
        args: [stackId],
      });
      card = randomCards[0];
    }

  } else {
    // Für nicht-eigene Stacks: Random
    const { rows: randomRows } = await db.execute({
      sql: `SELECT * FROM cards WHERE stack_id=? ORDER BY RANDOM() LIMIT 1`,
      args: [stackId],
    });
    card = randomRows[0];
  }

  res.json(card || null);
});

// Review a card
router.post("/stacks/:stackId/cards/:cardId/review", requireAuth, async (req, res) => {
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

  // Get current max review_sequence for this stack and user
  const { rows: maxSeqRows } = await db.execute({
    sql: `SELECT COALESCE(MAX(review_sequence), 0) as max_seq FROM cards WHERE stack_id = ?`,
    args: [stackId]
  });
  const currentMaxSeq = maxSeqRows[0].max_seq;
  
  // Calculate new review_sequence
  let newReviewSeq;
  if (rating === "hard") {
    // For "hard": Add 7-10 cards before this one can appear again
    const cardsDelay = Math.floor(Math.random() * 4) + 7; // Random between 7-10
    newReviewSeq = currentMaxSeq + cardsDelay;
  } else {
    // For "good" and "easy": Normal sequence (will be filtered by due_at)
    newReviewSeq = currentMaxSeq + 1;
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
});

export default router;
