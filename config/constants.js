export const JWT_SECRET = process.env.JWT_SECRET || "fallback-secret";

export const boxIntervals = [0, 1, 3, 7, 16, 35];

export const corsConfig = {
  origin: "*",
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-API-Key"],
};
