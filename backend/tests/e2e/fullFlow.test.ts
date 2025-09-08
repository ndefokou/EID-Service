import request from 'supertest';
import app from '../../src/app'; // Assuming your Express app is exported from src/app.ts
import mongoose from 'mongoose';
import { User } from '../../src/models/User';
import { EidSession } from '../../src/models/EidSession';
import { EID_CONFIG } from '../../config/eid'; // Adjust path as needed

describe('End-to-End eID Full Flow', () => {
  beforeAll(async () => {
    // Connect to a test database or clear the existing one
    await mongoose.connect(process.env.MONGO_URI_TEST || 'mongodb://localhost:27017/eid_service_test_e2e');
    await User.deleteMany({});
    await EidSession.deleteMany({});
  });

  afterAll(async () => {
    // Disconnect from the database
    await mongoose.disconnect();
  });

  beforeEach(async () => {
    // Clear data before each test to ensure isolation
    await User.deleteMany({});
    await EidSession.deleteMany({});
  });

  it('should complete the full eID authentication and attribute release flow', async () => {
    // 1. Initiate eID session (simulated)
    const initiateResponse = await request(app)
      .post('/api/v1/eid/initiate')
      .send({
        requestedAttributes: [
          { oid: '1.2.276.0.76.4.29', required: true, status: 'required' }, // FamilyName
          { oid: '1.2.276.0.76.4.15', required: true, status: 'required' }, // GivenNames
        ],
      })
      .expect(200);

    const { sessionId, redirectUrl } = initiateResponse.body;
    expect(sessionId).toBeDefined();
    expect(redirectUrl).toContain(EID_CONFIG.EID_CLIENT_BASE_URL); // Verify redirect to eID client

    // 2. Simulate eID Client redirecting back to RP callback URL (simulated success)
    // In a real scenario, the eID client would redirect with a SAMLResponse or similar.
    // For E2E, we simulate the callback with an assumed success state and data.
    const callbackResponse = await request(app)
      .post(`/api/v1/eid/callback?sessionId=${sessionId}`)
      .send({
        // This data would typically come from the eID client after successful eID card interaction
        eidAttributes: {
          FamilyName: 'Doe',
          GivenNames: 'John',
          DateOfBirth: '1990-01-01',
        },
        signatureValid: true, // Assuming the eID client verified the signature
      })
      .expect(200);

    expect(callbackResponse.body.message).toBe('eID authentication successful.');
    expect(callbackResponse.body.token).toBeDefined();
    expect(callbackResponse.body.refreshToken).toBeDefined();
    expect(callbackResponse.body.user).toBeDefined();
    expect(callbackResponse.body.user.username).toBeDefined();
    expect(callbackResponse.body.user.firstName).toBe('John'); // Mapped attribute
    expect(callbackResponse.body.user.lastName).toBe('Doe');   // Mapped attribute

    // 3. Verify user profile can be fetched with the generated token
    const token = callbackResponse.body.token;
    const profileResponse = await request(app)
      .get('/api/v1/auth/profile')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(profileResponse.body.username).toBe(callbackResponse.body.user.username);
    expect(profileResponse.body.firstName).toBe('John');
    expect(profileResponse.body.lastName).toBe('Doe');

    // 4. Simulate token refresh
    const refreshToken = callbackResponse.body.refreshToken;
    const refreshResponse = await request(app)
      .post('/api/v1/auth/refresh-token')
      .send({ refreshToken })
      .expect(200);

    expect(refreshResponse.body.accessToken).toBeDefined();
    expect(refreshResponse.body.accessToken).not.toBe(token); // New token should be different

    // 5. Verify a protected route with the new access token
    const newProfileResponse = await request(app)
      .get('/api/v1/auth/profile')
      .set('Authorization', `Bearer ${refreshResponse.body.accessToken}`)
      .expect(200);
    
    expect(newProfileResponse.body.username).toBe(callbackResponse.body.user.username);

    // 6. Simulate logout
    const logoutResponse = await request(app)
      .post('/api/v1/auth/logout')
      .set('Authorization', `Bearer ${refreshResponse.body.accessToken}`) // Use any valid token
      .expect(200);

    expect(logoutResponse.body.message).toBe('Logged out successfully.');

    // 7. Verify that the refresh token is cleared from the user
    const loggedOutUser = await User.findById(callbackResponse.body.user.id);
    expect(loggedOutUser?.refreshToken).toBeUndefined();
  });

  // Add more E2E tests for edge cases, error handling, etc.
  it('should handle invalid eID session initiation', async () => {
    await request(app)
      .post('/api/v1/eid/initiate')
      .send({ requestedAttributes: [{ oid: 'invalid', required: true, status: 'required' }] })
      .expect(400); // Bad Request expected for invalid OID
  });

  it('should handle eID callback with invalid session ID', async () => {
    await request(app)
      .post('/api/v1/eid/callback?sessionId=invalidSessionId')
      .send({
        eidAttributes: { FamilyName: 'Doe' },
        signatureValid: true,
      })
      .expect(400); // Bad Request expected
  });

  it('should handle eID callback with invalid signature', async () => {
    const initiateResponse = await request(app)
      .post('/api/v1/eid/initiate')
      .send({
        requestedAttributes: [{ oid: '1.2.276.0.76.4.29', required: true, status: 'required' }],
      })
      .expect(200);

    const { sessionId } = initiateResponse.body;

    await request(app)
      .post(`/api/v1/eid/callback?sessionId=${sessionId}`)
      .send({
        eidAttributes: { FamilyName: 'Doe' },
        signatureValid: false, // Simulate invalid signature
      })
      .expect(401); // Unauthorized expected
  });
});