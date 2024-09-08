import jwt from 'jsonwebtoken';

export const verifyToken = (request, response, next) => {
  const token = request.cookies.jwt;

  // Check if the token exists
  if (!token) {
    return response.status(401).json({ message: "Authentication failed! No token provided." });
  }

  // Verify the token
  jwt.verify(token, process.env.JWT_KEY, (err, payload) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return response.status(401).json({ message: "Token has expired. Please log in again." });
      } else {
        return response.status(403).json({ message: "Invalid token. Access denied." });
      }
    }

    // Token is valid
    request.userId = payload.userId; // Attach user ID from token to request object
    next(); // Proceed to the next middleware or route handler
  });
};
