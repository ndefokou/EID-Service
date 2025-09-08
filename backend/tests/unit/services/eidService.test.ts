import { EidService } from '../../../src/services/eid/EidService';
import { SessionManager } from '../../../src/services/eid/SessionManager';
import { CertificateValidator } from '../../../src/services/eid/CertificateValidator';
import { SignatureVerifier } from '../../../src/services/eid/SignatureVerifier';
import { Tr03124Protocol } from '../../../src/services/eid/Tr03124Protocol';
import { UserRepository } from '../../../src/services/auth/UserRepository';
import { AuditLogger } from '../../../src/services/external/AuditLogger';
import { IEidSession } from '../../../src/models/EidSession';
import { EID_CONFIG } from '../../../config/eid';
import mongoose from 'mongoose';

// Mock dependencies
jest.mock('../../../src/services/eid/SessionManager');
jest.mock('../../../src/services/eid/CertificateValidator');
jest.mock('../../../src/services/eid/SignatureVerifier');
jest.mock('../../../src/services/eid/Tr03124Protocol');
jest.mock('../../../src/services/auth/UserRepository');
jest.mock('../../../src/services/external/AuditLogger');
jest.mock('../../../src/models/EidSession');
jest.mock('../../../src/models/User');

describe('EidService Unit Tests', () => {
  let eidService: EidService;
  let mockSessionManager: jest.Mocked<SessionManager>;
  let mockCertificateValidator: jest.Mocked<CertificateValidator>;
  let mockSignatureVerifier: jest.Mocked<SignatureVerifier>;
  let mockTr03124Protocol: jest.Mocked<Tr03124Protocol>;
  let mockUserRepository: jest.Mocked<UserRepository>;
  let mockAuditLogger: jest.Mocked<AuditLogger>;

  beforeEach(() => {
    // Clear all mocks before each test
    jest.clearAllMocks();

    // Get mocked instances
    mockSessionManager = SessionManager.prototype as jest.Mocked<SessionManager>;
    mockCertificateValidator = CertificateValidator.prototype as jest.Mocked<CertificateValidator>;
    mockSignatureVerifier = SignatureVerifier.prototype as jest.Mocked<SignatureVerifier>;
    mockTr03124Protocol = Tr03124Protocol.prototype as jest.Mocked<Tr03124Protocol>;
    mockUserRepository = UserRepository.prototype as jest.Mocked<UserRepository>;
    mockAuditLogger = AuditLogger.prototype as jest.Mocked<AuditLogger>;

    // Initialize EidService with mocked dependencies
    eidService = new EidService();
  });

  describe('startAuthentication', () => {
    it('should successfully start an eID authentication session', async () => {
      const userId = 'user123';
      const clientRedirectUrl = 'http://localhost:3000/callback';
      const requestedAttributes = ['FamilyName', 'GivenNames'];
      const mockSessionId = 'testSessionId';
      const mockNonce = 'testNonce';

      mockSessionManager.createSession.mockResolvedValueOnce({
        sessionId: mockSessionId,
        userId: userId,
        status: 'INITIATED',
        nonce: mockNonce,
        clientRedirectUrl: clientRedirectUrl,
        requestedAttributes: requestedAttributes,
        attributes: {},
        createdAt: new Date(),
        updatedAt: new Date(),
        _id: new mongoose.Types.ObjectId(),
      } as IEidSession);

      mockTr03124Protocol.generateAuthRequest.mockResolvedValueOnce({
        // Mock auth request payload
        challenge: 'mockChallenge',
        transactionId: 'mockTransactionId',
      });

      const result = await eidService.startAuthentication(userId, clientRedirectUrl, requestedAttributes);

      expect(mockSessionManager.createSession).toHaveBeenCalledWith(userId, clientRedirectUrl, requestedAttributes);
      expect(mockTr03124Protocol.generateAuthRequest).toHaveBeenCalledWith(
        mockSessionId,
        EID_CONFIG.RP_CALLBACK_URL
      );
      expect(result.sessionId).toBe(mockSessionId);
      expect(result.eidClientInteractionUrl).toContain(EID_CONFIG.EID_CLIENT_BASE_URL);
      expect(result.status).toBe('AUTHENTICATION_INITIATED');
    });

    it('should throw an error if session creation fails', async () => {
      const userId = 'user123';
      const clientRedirectUrl = 'http://localhost:3000/callback';
      const requestedAttributes = ['FamilyName'];
      mockSessionManager.createSession.mockRejectedValueOnce(new Error('Failed to create session'));

      await expect(eidService.startAuthentication(userId, clientRedirectUrl, requestedAttributes)).rejects.toThrow('Failed to create session');
    });
  });

  describe('processAuthenticationCallback', () => {
    it('should successfully process callback and update session', async () => {
      const sessionId = 'validSessionId';
      const eidResponse = { /* mock eID response data */ };
      const callbackData = { sessionId, eidResponse };
      const mockNonce = 'testNonce';
      const mockClientRedirectUrl = 'http://localhost:3000/eid-callback';
      const mockUserId = new mongoose.Types.ObjectId();
      const processedAttributes = { FamilyName: 'Doe', GivenNames: 'John' };

      const mockEidSession: IEidSession = {
        _id: mockUserId,
        userId: mockUserId.toString(),
        sessionId,
        status: 'INITIATED',
        statusDetail: undefined,
        nonce: mockNonce,
        clientRedirectUrl: mockClientRedirectUrl,
        requestedAttributes: ['FamilyName', 'GivenNames'],
        attributes: {},
        createdAt: new Date(),
        updatedAt: new Date(),
        expiresAt: undefined,
        rawEidResponse: undefined,
      } as IEidSession; // Cast to IEidSession to satisfy the interface

      mockSessionManager.getSession.mockResolvedValueOnce(mockEidSession);
      mockTr03124Protocol.processAuthResponse.mockResolvedValueOnce({
        status: 'SUCCESS',
        sessionId: sessionId,
        attributes: processedAttributes,
      });
      mockSessionManager.updateSessionStatus.mockResolvedValueOnce(mockEidSession);
      mockSessionManager.updateSessionAttributes.mockResolvedValueOnce(mockEidSession);


      const result = await eidService.processAuthenticationCallback(callbackData);

      expect(mockSessionManager.getSession).toHaveBeenCalledWith(sessionId);
      expect(mockTr03124Protocol.processAuthResponse).toHaveBeenCalledWith(eidResponse);
      expect(mockSessionManager.updateSessionStatus).toHaveBeenCalledWith(sessionId, 'COMPLETED', 'SUCCESS');
      expect(mockSessionManager.updateSessionAttributes).toHaveBeenCalledWith(sessionId, processedAttributes);
      expect(result.sessionId).toBe(sessionId);
      expect(result.status).toBe('SUCCESS');
      expect(result.attributes).toEqual(processedAttributes);
      expect(result.redirectUrl).toBe(mockClientRedirectUrl);
    });

    it('should throw an error if sessionId or eidResponse is missing', async () => {
      const callbackData = { /* missing sessionId or eidResponse */ };
      await expect(eidService.processAuthenticationCallback(callbackData)).rejects.toThrow('Invalid eID authentication callback data.');
    });

    it('should throw an error if session not found', async () => {
      const sessionId = 'nonExistentSessionId';
      const eidResponse = { /* mock eID response data */ };
      const callbackData = { sessionId, eidResponse };

      mockSessionManager.getSession.mockResolvedValueOnce(null);

      await expect(eidService.processAuthenticationCallback(callbackData)).rejects.toThrow('eID Session not found or expired.');
    });

    it('should throw an error if TR-03124 authentication fails', async () => {
      const sessionId = 'validSessionId';
      const eidResponse = { /* mock eID response data */ };
      const callbackData = { sessionId, eidResponse };
      const mockNonce = 'testNonce';
      const mockClientRedirectUrl = 'http://localhost:3000/eid-callback';
      const mockUserId = new mongoose.Types.ObjectId();

      const mockEidSession: IEidSession = {
        _id: mockUserId,
        userId: mockUserId.toString(),
        sessionId,
        status: 'INITIATED',
        statusDetail: undefined,
        nonce: mockNonce,
        clientRedirectUrl: mockClientRedirectUrl,
        requestedAttributes: ['FamilyName', 'GivenNames'],
        attributes: {},
        createdAt: new Date(),
        updatedAt: new Date(),
        expiresAt: undefined,
        rawEidResponse: undefined,
      } as IEidSession; // Cast to IEidSession to satisfy the interface

      mockSessionManager.getSession.mockResolvedValueOnce(mockEidSession);
      mockTr03124Protocol.processAuthResponse.mockResolvedValueOnce({
        status: 'FAILED',
        sessionId: sessionId,
        attributes: {},
      });

      await expect(eidService.processAuthenticationCallback(callbackData)).rejects.toThrow('eID authentication failed: FAILED');
      expect(mockSessionManager.updateSessionStatus).toHaveBeenCalledWith(sessionId, 'FAILED', 'FAILED');
    });
  });
});