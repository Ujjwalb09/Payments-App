const { User } = require("../db");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../config");

const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer "))
    return res.status(403).json({});

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.username) {
      req.username = decoded.username;
      return next();
    }
    return res.status(403).json({});
  } catch (error) {
    return res.status(403).json({});
  }
};

module.exports = authMiddleware;
