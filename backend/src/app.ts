import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { json, urlencoded } from 'body-parser';
import { SERVER_CONFIG } from '@config/server';
import { corsOptions } from '@config/cors';
import { connectDB } from '@config/database';
import { logger } from '@utils/logger';
import { errorHandler } from '@middleware/errorHandler';
import eidRoutes from '@routes/eidRoutes';
import userRoutes from '@routes/userRoutes';

const app = express();

// Connect to MongoDB
connectDB();

// Security Middleware
app.use(helmet());
app.use(cors(corsOptions));

// Body Parsers
app.use(json());
app.use(urlencoded({ extended: true }));

// API Routes
app.use(`${SERVER_CONFIG.API_PREFIX}/eid`, eidRoutes);
app.use(`${SERVER_CONFIG.API_PREFIX}/users`, userRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

// Error Handling Middleware
app.use(errorHandler);

export default app;