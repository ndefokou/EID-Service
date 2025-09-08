import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { logger } from '../utils/logger';

dotenv.config();

const DB_URI = process.env.DATABASE_URI || 'mongodb://localhost:27017/eid-service';

export const connectDB = async () => {
  try {
    await mongoose.connect(DB_URI);
    logger.info('MongoDB connected successfully.');
  } catch (error: any) {
    logger.error(`MongoDB connection error: ${error.message}`);
    process.exit(1); // Exit process with failure
  }
};

export const disconnectDB = async () => {
  try {
    await mongoose.disconnect();
    logger.info('MongoDB disconnected successfully.');
  } catch (error: any) {
    logger.error(`MongoDB disconnection error: ${error.message}`);
  }
};