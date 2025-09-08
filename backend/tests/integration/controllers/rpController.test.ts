import request from 'supertest';
import app from '../../../src/app'; // Adjust path as needed
import mongoose from 'mongoose';
import { User } from '../../../src/models/User';
import { logger } from '../../../src/utils/logger';

// Mock the logger to prevent test output from cluttering the console
jest.mock('../../../src/utils/logger', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}));

describe('rpController Integration Tests', () => {
  beforeAll(async () => {
    // Connect to a test database
    await mongoose.connect(process.env.MONGO_URI_TEST || 'mongodb://localhost:27017/eid_service_test_rp_controller');
  });

  afterAll(async () => {
    // Disconnect from the database
    await mongoose.disconnect();
  });

  beforeEach(async () => {
    // Clear the User collection before each test
    await User.deleteMany({});
  });

  describe('GET /api/v1/rp/config', () => {
    it('should return RP application configuration', async () => {
      const res = await request(app)
        .get('/api/v1/rp/config')
        .expect(200);

      expect(res.body.rpId).toBeDefined();
      expect(res.body.rpName).toBeDefined();
      expect(res.body.rpUrl).toBeDefined();
      expect(res.body.eIDClientBaseUrl).toBeDefined();
      expect(res.body.supportedAttributes).toBeDefined();
      expect(Array.isArray(res.body.supportedAttributes)).toBe(true);
      expect(logger.info).toHaveBeenCalledWith('RP configuration requested.');
    });
  });

  // Add more tests for error cases or specific configuration scenarios if needed
});