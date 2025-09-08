import { CorsOptions } from 'cors';

const allowedOrigins = [
  'http://localhost:8081', // Frontend development server
  'http://localhost:3000', // Old frontend development server
  'http://localhost:3001', // Backend development server (if frontend makes requests to itself)
  // Add other allowed origins for production or other environments
];

export const corsOptions: CorsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200,
};