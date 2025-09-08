import app from './app';
import { SERVER_CONFIG } from '@root/config/server';
import { logger } from '@root/utils/logger';

const PORT = SERVER_CONFIG.PORT;

app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT} in ${SERVER_CONFIG.NODE_ENV} mode`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err: Error) => {
  logger.error(`Unhandled Rejection: ${err.message}`, err.stack);
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err: Error) => {
  logger.error(`Uncaught Exception: ${err.message}`, err.stack);
  process.exit(1);
});