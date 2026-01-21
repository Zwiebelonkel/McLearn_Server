import db from "../db.js";

export const requireAdmin = async (req, res, next) => {
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
