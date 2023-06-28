const jwt = require("jsonwebtoken");

require("dotenv").config();

const verifyToken = (req, res, next) => {
  const token = req.headers["x-token"];

  if (!token) {
    return res.status(403).json({"status":"error","message": "A token is required for authentication"});
  }
  try {
    const decoded = jwt.verify(token, process.env.TOKEN_KEY);
    req.user = decoded;
  } catch (err) {
    return res.status(401).json({"status":"error","message": "Invalid Token"});
  }
  return next();
};

module.exports = verifyToken;