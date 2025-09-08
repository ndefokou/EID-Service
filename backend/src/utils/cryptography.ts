import crypto from 'crypto';
import { logger } from '../../utils/logger';

/**
 * Generates a cryptographically secure random nonce.
 * @param length The length of the nonce in bytes. Defaults to 16 bytes (128 bits).
 * @returns A base64-encoded random nonce.
 */
export function generateNonce(length: number = 16): string {
  try {
    const nonce = crypto.randomBytes(length).toString('base64');
    logger.debug(`Generated nonce of length ${length} bytes.`);
    return nonce;
  } catch (error) {
    logger.error('Failed to generate nonce:', error);
    throw new Error('Failed to generate nonce.');
  }
}

/**
 * Hashes data using a specified algorithm.
 * @param data The data to hash (Buffer or string).
 * @param algorithm The hashing algorithm (e.g., 'sha256', 'sha512'). Defaults to 'sha256'.
 * @param encoding The output encoding. Defaults to 'hex'.
 * @returns The hashed data as a string.
 */
export function hashData(data: string | Buffer, algorithm: string = 'sha256', encoding: crypto.BinaryToTextEncoding = 'hex'): string {
  try {
    const hash = crypto.createHash(algorithm).update(data).digest(encoding);
    logger.debug(`Hashed data using ${algorithm} algorithm.`);
    return hash;
  } catch (error) {
    logger.error(`Failed to hash data with ${algorithm}:`, error);
    throw new Error(`Failed to hash data with ${algorithm}.`);
  }
}

/**
 * Verifies a digital signature.
 * @param algorithm The signature algorithm (e.g., 'RSA-SHA256').
 * @param data The original data that was signed.
 * @param signature The digital signature to verify (Buffer or string).
 * @param publicKey The public key for verification (PEM format).
 * @param encoding The encoding of the signature. Defaults to 'base64'.
 * @returns True if the signature is valid, false otherwise.
 */
export function verifySignature(
  algorithm: string,
  data: string | Buffer,
  signature: string | Buffer,
  publicKey: string | Buffer,
  encoding: crypto.BinaryToTextEncoding = 'base64'
): boolean {
  try {
    const verifier = crypto.createVerify(algorithm);
    verifier.update(data);
    const isValid = verifier.verify(publicKey, signature as string, encoding);
    if (isValid) {
      logger.debug(`Signature verified successfully using ${algorithm}.`);
    } else {
      logger.warn(`Signature verification failed using ${algorithm}.`);
    }
    return isValid;
  } catch (error) {
    logger.error(`Error during signature verification with ${algorithm}:`, error);
    // Depending on security requirements, you might re-throw or return false for errors
    return false;
  }
}

/**
 * Signs data using a private key.
 * @param algorithm The signing algorithm (e.g., 'RSA-SHA256').
 * @param data The data to sign.
 * @param privateKey The private key for signing (PEM format).
 * @param encoding The output encoding for the signature. Defaults to 'base64'.
 * @returns The digital signature as a string.
 */
export function signData(
  algorithm: string,
  data: string | Buffer,
  privateKey: string | Buffer,
  encoding: crypto.BinaryToTextEncoding = 'base64'
): string {
  try {
    const signer = crypto.createSign(algorithm);
    signer.update(data);
    const signature = signer.sign(privateKey, encoding);
    logger.debug(`Data signed successfully using ${algorithm}.`);
    return signature;
  } catch (error) {
    logger.error(`Error during data signing with ${algorithm}:`, error);
    throw new Error(`Failed to sign data with ${algorithm}.`);
  }
}

/**
 * Generates a universally unique identifier (UUID) using the 'v4' algorithm.
 * @returns A UUID string.
 */
export function generateUuid(): string {
  // UUID v4 is typically generated using Math.random(), but for cryptographically secure UUIDs,
  // it's better to leverage crypto.randomBytes as done in 'uuid' library or directly.
  // For simplicity and common use, a basic UUID v4 implementation is fine here,
  // but if truly cryptographically secure UUIDs are needed for all cases,
  // consider integrating a dedicated library like 'uuid' (uuid.v4()).
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = crypto.randomBytes(1)[0] % 16;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}