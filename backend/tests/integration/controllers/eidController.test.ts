import request from 'supertest';
import app from '../../../src/app'; // Adjust path as needed
import mongoose from 'mongoose';
import { EidSession } from '../../../src/models/EidSession';
import { EID_CONFIG } from '../../../config/eid'; // Adjust path as needed
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

describe('eidController Integration Tests', () => {
  beforeAll(async () => {
    // Connect to a test database
    await mongoose.connect(process.env.MONGO_URI_TEST || 'mongodb://localhost:27017/eid_service_test_controller');
  });

  afterAll(async () => {
    // Disconnect from the database
    await mongoose.disconnect();
  });

  beforeEach(async () => {
    // Clear the EidSession collection before each test
    await EidSession.deleteMany({});
  });

  describe('POST /api/v1/eid/initiate', () => {
    it('should initiate an eID session and return a redirect URL', async () => {
      const requestedAttributes = [
        { oid: '1.2.276.0.76.4.29', required: true, status: 'required' }, // FamilyName
        { oid: '1.2.276.0.76.4.15', required: true, status: 'required' }, // GivenNames
      ];

      const res = await request(app)
        .post('/api/v1/eid/initiate')
        .send({ requestedAttributes })
        .expect(200);

      expect(res.body.sessionId).toBeDefined();
      expect(res.body.redirectUrl).toBeDefined();
      expect(res.body.redirectUrl).toContain(EID_CONFIG.EID_CLIENT_BASE_URL);

      const session = await EidSession.findById(res.body.sessionId);
      expect(session).toBeDefined();
      expect(session?.nonce).toBeDefined();
      expect(session?.status).toBe('INITIATED');
      expect(session?.requestedAttributes.length).toBe(requestedAttributes.length);
    });

    it('should return 400 if no required attributes are provided', async () => {
      const res = await request(app)
        .post('/api/v1/eid/initiate')
        .send({ requestedAttributes: [] })
        .expect(400);

      expect(res.body.message).toBe('Requested attributes must be provided.');
    });

    it('should return 400 if requiredAttributes is missing', async () => {
      const res = await request(app)
        .post('/api/v1/eid/initiate')
        .send({})
        .expect(400);

      expect(res.body.message).toBe('Requested attributes must be provided.');
    });
  });

  describe('POST /api/v1/eid/callback', () => {
    it('should successfully process the eID callback and authenticate the user', async () => {
      // First, initiate a session to get a valid sessionId and nonce
      const initiateRes = await request(app)
        .post('/api/v1/eid/initiate')
        .send({
          requestedAttributes: [
            { oid: '1.2.276.0.76.4.29', required: true, status: 'required' }, // FamilyName
            { oid: '1.2.276.0.76.4.15', required: true, status: 'required' }, // GivenNames
          ],
        });

      const { sessionId } = initiateRes.body;

      const eidAttributes = {
        FamilyName: 'TestUser',
        GivenNames: 'Integration',
        DateOfBirth: '1990-05-15',
      };

      const res = await request(app)
        .post(`/api/v1/eid/callback?sessionId=${sessionId}`)
        .send({ eidAttributes, signatureValid: true })
        .expect(200);

      expect(res.body.message).toBe('eID authentication successful.');
      expect(res.body.token).toBeDefined();
      expect(res.body.refreshToken).toBeDefined();
      expect(res.body.user).toBeDefined();
      expect(res.body.user.firstName).toBe('Integration');
      expect(res.body.user.lastName).toBe('TestUser');

      const session = await EidSession.findById(sessionId);
      expect(session?.status).toBe('SUCCESS');
      expect(session?.rawEidResponse).toEqual(eidAttributes);
    });

    it('should return 400 if sessionId is missing', async () => {
      const res = await request(app)
        .post('/api/v1/eid/callback')
        .send({ eidAttributes: { FamilyName: 'Test' }, signatureValid: true })
        .expect(400);

      expect(res.body.message).toBe('Session ID is required.');
    });

    it('should return 400 if eidAttributes are missing', async () => {
      const initiateRes = await request(app)
        .post('/api/v1/eid/initiate')
        .send({
          requestedAttributes: [{ oid: '1.2.276.0.76.4.29', required: true, status: 'required' }],
        });
      const { sessionId } = initiateRes.body;

      const res = await request(app)
        .post(`/api/v1/eid/callback?sessionId=${sessionId}`)
        .send({ signatureValid: true })
        .expect(400);

      expect(res.body.message).toBe('eID attributes are required.');
    });

    it('should return 401 if signature is not valid', async () => {
      const initiateRes = await request(app)
        .post('/api/v1/eid/initiate')
        .send({
          requestedAttributes: [{ oid: '1.2.276.0.76.4.29', required: true, status: 'required' }],
        });
      const { sessionId } = initiateRes.body;

      const res = await request(app)
        .post(`/api/v1/eid/callback?sessionId=${sessionId}`)
        .send({ eidAttributes: { FamilyName: 'Test' }, signatureValid: false })
        .expect(401);

      expect(res.body.message).toBe('eID signature verification failed.');
    });

    it('should return 404 if session is not found', async () => {
      const res = await request(app)
        .post('/api/v1/eid/callback?sessionId=nonexistentId')
        .send({ eidAttributes: { FamilyName: 'Test' }, signatureValid: true })
        .expect(404);

      expect(res.body.message).toBe('eID session not found or expired.');
    });
  });
});