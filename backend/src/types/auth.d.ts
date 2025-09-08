import { IUser } from '../models/User'; // Adjust path as necessary based on your project structure

// This augments the Request type from Express to include a 'user' property.
// This is typically set by authentication middleware (e.g., Passport.js).
declare global {
  namespace Express {
    interface Request {
      user?: jwt.JwtPayload; // The authenticated user object with JWT payload structure
    }
  }
}

// Optionally, if you're using JWTs and want to type the decoded payload
declare module 'jsonwebtoken' {
  export interface JwtPayload {
    id: string;
    username: string;
    // Add other properties you store in the JWT payload
  }
}