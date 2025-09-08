import rateLimit from 'express-rate-limit';
import { Request, Response, NextFunction } from 'express'; // Added for typing
import { SERVER_CONFIG } from '../../config/server'; // Adjusted path
import { logger } from '../../utils/logger'; // Adjusted path

export const apiLimiter = rateLimit({
  windowMs: SERVER_CONFIG.RATE_LIMIT_WINDOW_MS, // 1 minute
  max: SERVER_CONFIG.RATE_LIMIT_MAX_REQUESTS, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again after 1 minute',
  handler: (req: Request, res: Response, next: NextFunction) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      success: false,
      message: 'Too many requests, please try again later.',
    });
  },
});

// You can create other specific rate limiters if needed, e.g., for login attempts
export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login requests per windowMs
  message: 'Too many login attempts from this IP, please try again after 15 minutes',
  handler: (req: Request, res: Response, next: NextFunction) => {
    logger.warn(`Login rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      success: false,
      message: 'Too many login attempts, please try again after 15 minutes.',
    });
  },
});