import request from 'supertest';
import app from '../../../src/app';
import mongoose from 'mongoose';
import { EidSession } from '../../../src/models/EidSession';
import { User } from '../../../src/models/User';
import { EID_CONFIG } from '../../../config/eid';
import { logger } from '../../../src/utils/logger';

jest.mock('../../../src/utils/logger', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}));

describe('eID Routes Integration Tests', () => {
  beforeAll(async () => {
    await mongoose.connect(process.env.MONGO_URI_TEST || 'mongodb://localhost:27017/eid_service_test_routes');
  });

  afterAll(async () => {
    await mongoose.disconnect();
  });

  beforeEach(async () => {
    await EidSession.deleteMany({});
    await User.deleteMany({});
  });

  describe('POST /api/v1/eid/initiate', () => {
    it('should successfully initiate an eID session', async () => {
      const requestedAttributes = [
        { oid: '1.2.276.0.76.4.29', required: true, status: 'required' }, // FamilyName
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
      expect(session?.status).toBe('INITIATED');
      expect(session?.requestedAttributes.length).toBe(requestedAttributes.length);
    });

    it('should return 400 for missing requested attributes', async () => {
      const res = await request(app)
        .post('/api/v1/eid/initiate')
        .send({})
        .expect(400);

      expect(res.body.message).toBe('Requested attributes must be provided.');
    });
  });

  describe('POST /api/v1/eid/callback', () => {
    it('should successfully process eID callback and create/authenticate user', async () => {
      const initiateRes = await request(app)
        .post('/api/v1/eid/initiate')
        .send({ requestedAttributes: [{ oid: '1.2.276.0.76.4.29', required: true, status: 'required' }] });
      const { sessionId } = initiateRes.body;

      const eidAttributes = {
        FamilyName: 'RouteTest',
        GivenNames: 'eID',
      };

      const res = await request(app)
        .post(`/api/v1/eid/callback?sessionId=${sessionId}`)
        .send({ eidAttributes, signatureValid: true })
        .expect(200);

      expect(res.body.message).toBe('eID authentication successful.');
      expect(res.body.token).toBeDefined();
      expect(res.body.user).toBeDefined();
      expect(res.body.user.lastName).toBe('RouteTest');

      const session = await EidSession.findById(sessionId);
      expect(session?.status).toBe('COMPLETED');
      expect(session?.rawEidResponse).toEqual(eidAttributes);
      expect(session?.userId).toBeDefined();
    });

    it('should return 400 for invalid session ID', async () => {
      await request(app)
        .post('/api/v1/eid/callback?sessionId=invalid')
        .send({ eidAttributes: { FamilyName: 'Test' }, signatureValid: true })
        .expect(400);
    });

    it('should return 401 for invalid signature', async () => {
      const initiateRes = await request(app)
        .post('/api/v1/eid/initiate')
        .send({ requestedAttributes: [{ oid: '1.2.276.0.76.4.29', required: true, status: 'required' }] });
      const { sessionId } = initiateRes.body;

      await request(app)
        .post(`/api/v1/eid/callback?sessionId=${sessionId}`)
        .send({ eidAttributes: { FamilyName: 'Test' }, signatureValid: false })
        .expect(401);
    });
  });
});