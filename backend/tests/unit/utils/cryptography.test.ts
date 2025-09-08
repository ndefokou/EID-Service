import { generateNonce, hashData, verifySignature, signData } from '../../../src/utils/cryptography';
import crypto from 'crypto';

// Mock crypto functions for consistent testing
jest.mock('crypto', () => ({
  ...jest.requireActual('crypto'), // Import and retain default behavior
  randomBytes: jest.fn(),
  createHash: jest.fn(() => ({
    update: jest.fn().mockReturnThis(),
    digest: jest.fn(),
  })),
  createSign: jest.fn(() => ({
    update: jest.fn().mockReturnThis(),
    sign: jest.fn(),
  })),
  createVerify: jest.fn(() => ({
    update: jest.fn().mockReturnThis(),
    verify: jest.fn(),
  })),
}));

describe('Cryptography Utility Functions', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('generateNonce', () => {
    it('should generate a nonce of the specified length', () => {
      const mockBuffer = Buffer.from('testnonce12345');
      (crypto.randomBytes as jest.Mock).mockReturnValueOnce(mockBuffer);

      const nonce = generateNonce(16); // 16 bytes = 32 hex characters
      expect(crypto.randomBytes).toHaveBeenCalledWith(16);
      expect(nonce).toBe(mockBuffer.toString('hex'));
    });

    it('should default to a 32-byte nonce if no length is provided', () => {
      const mockBuffer = Buffer.from('defaultnonce....................'); // 32 bytes
      (crypto.randomBytes as jest.Mock).mockReturnValueOnce(mockBuffer);

      const nonce = generateNonce();
      expect(crypto.randomBytes).toHaveBeenCalledWith(32);
      expect(nonce).toBe(mockBuffer.toString('hex'));
    });
  });

  describe('hashData', () => {
    it('should hash the provided data using SHA256 by default', () => {
      const data = 'some data to hash';
      const mockDigest = 'hasheddata';
      (crypto.createHash as jest.Mock).mockReturnValueOnce({
        update: jest.fn().mockReturnThis(),
        digest: jest.fn().mockReturnValueOnce(mockDigest),
      });

      const hash = hashData(data);
      expect(crypto.createHash).toHaveBeenCalledWith('sha256');
      expect((crypto.createHash as jest.Mock).mock.results[0].value.update).toHaveBeenCalledWith(data);
      expect(hash).toBe(mockDigest);
    });

    it('should hash data with a specified algorithm', () => {
      const data = 'another data';
      const algorithm = 'sha512';
      const mockDigest = 'sha512hasheddata';
      (crypto.createHash as jest.Mock).mockReturnValueOnce({
        update: jest.fn().mockReturnThis(),
        digest: jest.fn().mockReturnValueOnce(mockDigest),
      });

      const hash = hashData(data, algorithm);
      expect(crypto.createHash).toHaveBeenCalledWith(algorithm);
      expect(hash).toBe(mockDigest);
    });
  });

  describe('signData', () => {
    it('should sign data using the provided private key', () => {
      const data = 'data to sign';
      const privateKey = '-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----';
      const mockSignature = 'mocksignature';

      (crypto.createSign as jest.Mock).mockReturnValueOnce({
        update: jest.fn().mockReturnThis(),
        sign: jest.fn().mockReturnValueOnce(mockSignature),
      });

      const signature = signData('SHA256', data, privateKey);
      expect(crypto.createSign).toHaveBeenCalledWith('SHA256');
      expect((crypto.createSign as jest.Mock).mock.results[0].value.update).toHaveBeenCalledWith(data);
      expect((crypto.createSign as jest.Mock).mock.results[0].value.sign).toHaveBeenCalledWith(privateKey, 'base64');
      expect(signature).toBe(mockSignature);
    });
  });

  describe('verifySignature', () => {
    it('should verify a valid signature', () => {
      const data = 'data to verify';
      const publicKey = '-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----';
      const signature = 'validsignature';

      (crypto.createVerify as jest.Mock).mockReturnValueOnce({
        update: jest.fn().mockReturnThis(),
        verify: jest.fn().mockReturnValueOnce(true),
      });

      const isValid = verifySignature('SHA256', data, signature, publicKey);
      expect(crypto.createVerify).toHaveBeenCalledWith('SHA256');
      expect((crypto.createVerify as jest.Mock).mock.results[0].value.update).toHaveBeenCalledWith(data);
      expect((crypto.createVerify as jest.Mock).mock.results[0].value.verify).toHaveBeenCalledWith(publicKey, signature, 'base64');
      expect(isValid).toBe(true);
    });

    it('should return false for an invalid signature', () => {
      const data = 'data to verify';
      const publicKey = '-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----';
      const signature = 'invalidsignature';

      (crypto.createVerify as jest.Mock).mockReturnValueOnce({
        update: jest.fn().mockReturnThis(),
        verify: jest.fn().mockReturnValueOnce(false),
      });

      const isValid = verifySignature('SHA256', data, signature, publicKey);
      expect(isValid).toBe(false);
    });
  });
});