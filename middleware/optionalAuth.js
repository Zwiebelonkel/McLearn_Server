import jwt from "jsonwebtoken";
import { JWT_SECRET } from "../config/constants.js";

export const optionalAuth = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) {
    req.user = null;
    return next();
  }

  const token = auth.replace("Bearer ", "");
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
  } catch (err) {
    req.user = null;
  }
  next();
};
