import dotenv from 'dotenv';

dotenv.config();

export const SESSION_CONFIG = {
  SECRET: process.env.SESSION_SECRET || 'your_session_secret_key_here',
  NAME: process.env.SESSION_NAME || 'eid.sid',
  RESAVE: process.env.SESSION_RESAVE === 'true',
  SAVE_UNINITIALIZED: process.env.SESSION_SAVE_UNINITIALIZED === 'true',
  COOKIE_SECURE: process.env.SESSION_COOKIE_SECURE === 'true', // Set to true in production
  COOKIE_HTTP_ONLY: process.env.SESSION_COOKIE_HTTP_ONLY === 'true',
  COOKIE_MAX_AGE: parseInt(process.env.SESSION_COOKIE_MAX_AGE || '3600000', 10), // 1 hour in milliseconds
};