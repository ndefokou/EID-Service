import { Request, Response, NextFunction } from 'express';
import { logger } from '../../utils/logger';

export const errorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  logger.error(`Error: ${err.message}`, { stack: err.stack, path: req.path });

  const statusCode = err.statusCode || 500;
  const message = err.message || 'An unexpected error occurred.';

  res.status(statusCode).json({
    success: false,
    message: message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
  });
};