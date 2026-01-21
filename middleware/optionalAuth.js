import jwt from "jsonwebtoken";

export const optionalAuth = (req, _res, next) => {
  const header = req.headers.authorization;
  if (header?.startsWith("Bearer ")) {
    try {
      req.user = jwt.verify(header.split(" ")[1], process.env.JWT_SECRET);
    } catch {}
  }
  next();
};
