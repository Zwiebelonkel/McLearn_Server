import "dotenv/config";
import express from "express";
import cors from "cors";
import { corsConfig } from "./config/constants.js";

// Middleware
import { requireAuth } from "./middleware/requireAuth.js";
import { optionalAuth } from "./middleware/optionalAuth.js";

// Routes
import authRoutes from "./routes/auth.routes.js";
import usersRoutes from "./routes/users.routes.js";
import stacksRoutes from "./routes/stacks.routes.js";
import cardsRoutes from "./routes/cards.routes.js";
import collaboratorsRoutes from "./routes/collaborators.routes.js";
import friendsRoutes from "./routes/friends.routes.js";
import scribblepadRoutes from "./routes/scribblepad.routes.js";
import statisticsRoutes from "./routes/statistics.routes.js";
import adminRoutes from "./routes/admin.routes.js";

const app = express();

// Middleware
app.use(cors(corsConfig));
app.use(express.json());

// Health check
app.get("/api/health", (_req, res) => res.json({ ok: true }));

// Mount routes
app.use("/api", authRoutes);
app.use("/api/users", usersRoutes);
app.use("/api/stacks", stacksRoutes);
app.use("/api/cards", cardsRoutes);
app.use("/api/stacks/:stackId/collaborators", collaboratorsRoutes);
app.use("/api/friends", friendsRoutes);
app.use("/api/scribblepad", scribblepadRoutes);
app.use("/api/statistics", statisticsRoutes);
app.use("/api/admin", adminRoutes);

// Start server
const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`✅ Yappy läuft auf http://localhost:${port}`);
});
