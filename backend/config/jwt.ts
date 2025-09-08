import dotenv from 'dotenv';
import { Secret } from 'jsonwebtoken';

dotenv.config();

export const JWT_CONFIG = {
  SECRET: process.env.JWT_SECRET! as Secret, // Assumed to be always defined after dotenv.config()
  EXPIRATION_TIME: process.env.JWT_EXPIRATION_TIME || '1h', // e.g., '1h', '7d', '24h'
  REFRESH_SECRET: process.env.JWT_REFRESH_SECRET! as Secret, // Assumed to be always defined after dotenv.config()
  REFRESH_EXPIRATION_TIME: process.env.JWT_REFRESH_EXPIRATION_TIME || '7d', // e.g., '7d', '30d'
};