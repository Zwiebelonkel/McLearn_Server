import { Router } from "express";
import db from "../db.js";
import { optionalAuth } from "../middleware/optionalAuth.js";

const router = Router();

// Stack statistics
router.get("/stacks/:stackId", optionalAuth, async (req, res) => {
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

  // Most reviewed cards
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

  // Hardest cards
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

  // Easiest cards
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

// User statistics
router.get("/users/:userId", optionalAuth, async (req, res) => {
  const { userId } = req.params;

  // Check if viewing own profile
  const isOwnProfile = req.user && req.user.id === parseInt(userId);
  
  // Build WHERE clause
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

  // Anonymize private stacks if not own profile
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

  // Box Distribution
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

  // Weekly Review Stats
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

export default router;
