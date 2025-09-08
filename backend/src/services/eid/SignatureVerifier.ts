import { logger } from '@root/utils/logger';
import { EID_CONFIG } from '@root/config/eid';
import { CertificateValidator } from './CertificateValidator';
import { createVerify, publicEncrypt, constants } from 'crypto';
import fs from 'fs';
import path from 'path';
import validator from 'validator';
import { Certificate } from '@fidm/x509';

/**
 * Custom error class for signature verification failures
 */
export class SignatureVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SignatureVerificationError';
  }
}

/**
 * Service for verifying digital signatures in the eID ecosystem.
 * Supports verification of signatures from eID servers and clients using
 * cryptographic algorithms and certificate validation.
 */
export class SignatureVerifier {
  private readonly certificateValidator: CertificateValidator;

  constructor() {
    try {
      this.certificateValidator = new CertificateValidator();
      logger.info('SignatureVerifier initialized successfully');
    } catch (error) {
      const errorMessage = `Failed to initialize SignatureVerifier: ${(error as Error).message}`;
      logger.error(errorMessage);
      throw new SignatureVerificationError(errorMessage);
    }
  }

  /**
   * Verifies a digital signature using a public key or certificate.
   * @param signedData The data that was signed (string or Buffer).
   * @param signature The signature to verify (hex or base64 encoded).
   * @param publicKeyPem The public key or certificate in PEM format.
   * @param algorithm The signing algorithm (default: 'sha256').
   * @returns True if the signature is valid, false otherwise.
   * @throws SignatureVerificationError on critical errors.
   */
  public async verifySignature(
    signedData: string | Buffer,
    signature: string,
    publicKeyPem: string,
    algorithm: string = 'sha256'
  ): Promise<boolean> {
    const verificationId = `sig_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    logger.debug('Starting digital signature verification', { verificationId, algorithm });

    // Input validation
    if (!signedData || !signature || !publicKeyPem) {
      logger.warn('Missing required parameters for signature verification', { verificationId });
      throw new SignatureVerificationError('Missing signedData, signature, or publicKeyPem');
    }
    if (!validator.isAscii(signedData.toString()) || !validator.isAscii(publicKeyPem)) {
      logger.warn('Invalid input format for signedData or publicKeyPem', { verificationId });
      throw new SignatureVerificationError('Invalid input format for signedData or publicKeyPem');
    }
    if (!['sha256', 'sha384', 'sha512'].includes(algorithm.toLowerCase())) {
      logger.warn(`Unsupported signing algorithm: ${algorithm}`, { verificationId });
      throw new SignatureVerificationError(`Unsupported signing algorithm: ${algorithm}`);
    }

    try {
      // Validate certificate or public key
      let publicKey = publicKeyPem;
      if (publicKeyPem.includes('-----BEGIN CERTIFICATE-----')) {
        const validationResult = await this.certificateValidator.validateCertificate(publicKeyPem);
        if (!validationResult.isValid) {
          logger.error('Certificate validation failed', { verificationId, errors: validationResult.errors });
          throw new SignatureVerificationError(`Certificate validation failed: ${validationResult.errors.join(', ')}`);
        }
        const cert = Certificate.fromPEM(Buffer.from(publicKeyPem));
        publicKey = cert.publicKey.toPEM();
      } else if (!publicKeyPem.includes('-----BEGIN PUBLIC KEY-----')) {
        logger.warn('Invalid public key PEM format', { verificationId });
        throw new SignatureVerificationError('Invalid public key PEM format');
      }

      // Convert signature to Buffer (handle hex or base64)
      let signatureBuffer: Buffer;
      try {
        signatureBuffer = Buffer.from(signature, signature.startsWith('MII') ? 'base64' : 'hex');
      } catch (error) {
        logger.warn('Invalid signature format', { verificationId, error: (error as Error).message });
        throw new SignatureVerificationError('Invalid signature format: Must be hex or base64');
      }

      // Perform signature verification
      const verifier = createVerify(`RSA-${algorithm.toUpperCase()}`);
      verifier.update(signedData);
      const isValid = verifier.verify(
        {
          key: publicKey,
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
        },
        signatureBuffer
      );

      logger.info('Signature verification completed', {
        verificationId,
        isValid,
        algorithm,
      });

      return isValid;
    } catch (error) {
      const errorMessage = `Signature verification failed: ${(error as Error).message}`;
      logger.error(errorMessage, { verificationId, error });
      throw new SignatureVerificationError(errorMessage);
    }
  }

  /**
   * Verifies the signature of an eID server response.
   * @param responsePayload The eID server response payload.
   * @param signature The signature provided by the eID server (hex or base64).
   * @returns True if the signature is valid, false otherwise.
   * @throws SignatureVerificationError on critical errors.
   */
  public async verifyEidServerResponseSignature(responsePayload: any, signature: string): Promise<boolean> {
    const verificationId = `eid_server_sig_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    logger.debug('Verifying eID server response signature', { verificationId });

    try {
      // Validate inputs
      if (!responsePayload || !signature) {
        logger.warn('Missing responsePayload or signature for eID server verification', { verificationId });
        throw new SignatureVerificationError('Missing responsePayload or signature');
      }

      // Load and validate eID server certificate
      const certPath = path.resolve(EID_CONFIG.EID_SERVER_CERTIFICATE_PATH);
      let eidServerCertificate: string;
      try {
        fs.accessSync(certPath, fs.constants.R_OK);
        eidServerCertificate = fs.readFileSync(certPath, 'utf8').trim();
        if (!eidServerCertificate.includes('-----BEGIN CERTIFICATE-----')) {
          throw new Error('Invalid certificate PEM format');
        }
      } catch (error) {
        const errorMessage = `Failed to load eID server certificate from ${certPath}: ${(error as Error).message}`;
        logger.error(errorMessage, { verificationId });
        throw new SignatureVerificationError(errorMessage);
      }

      // Validate certificate
      const validationResult = await this.certificateValidator.validateCertificate(eidServerCertificate);
      if (!validationResult.isValid) {
        logger.error('eID server certificate validation failed', {
          verificationId,
          errors: validationResult.errors,
        });
        throw new SignatureVerificationError(`eID server certificate validation failed: ${validationResult.errors.join(', ')}`);
      }

      // Serialize payload to string
      let payloadString: string;
      try {
        payloadString = JSON.stringify(responsePayload);
      } catch (error) {
        logger.warn('Failed to serialize response payload', { verificationId, error: (error as Error).message });
        throw new SignatureVerificationError('Invalid response payload format');
      }

      // Verify signature
      const isValid = await this.verifySignature(payloadString, signature, eidServerCertificate);
      logger.info('eID server response signature verification completed', { verificationId, isValid });
      return isValid;
    } catch (error) {
      const errorMessage = `eID server response signature verification failed: ${(error as Error).message}`;
      logger.error(errorMessage, { verificationId, error });
      throw error instanceof SignatureVerificationError
        ? error
        : new SignatureVerificationError(errorMessage);
    }
  }

  /**
   * Verifies a signature from an eID card/client.
   * @param signedData The data signed by the eID card/client.
   * @param signature The signature provided by the eID card/client (hex or base64).
   * @param certificatePem The eID card/client certificate in PEM format.
   * @param algorithm The signing algorithm (default: 'sha256').
   * @returns True if the signature is valid, false otherwise.
   * @throws SignatureVerificationError on critical errors.
   */
  public async verifyEidCardSignature(
    signedData: string | Buffer,
    signature: string,
    certificatePem: string,
    algorithm: string = 'sha256'
  ): Promise<boolean> {
    const verificationId = `eid_card_sig_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    logger.debug('Verifying eID card/client signature', { verificationId, algorithm });

    try {
      // Validate inputs
      if (!signedData || !signature || !certificatePem) {
        logger.warn('Missing parameters for eID card signature verification', { verificationId });
        throw new SignatureVerificationError('Missing signedData, signature, or certificatePem');
      }
      if (!certificatePem.includes('-----BEGIN CERTIFICATE-----')) {
        logger.warn('Invalid certificate PEM format for eID card', { verificationId });
        throw new SignatureVerificationError('Invalid certificate PEM format');
      }

      // Validate certificate with TR-03124 EAC requirements
      const validationResult = await this.certificateValidator.validateTr03124EacCertificate(certificatePem);
      if (!validationResult.isValid) {
        logger.error('eID card certificate validation failed', {
          verificationId,
          errors: validationResult.errors,
        });
        throw new SignatureVerificationError(`eID card certificate validation failed: ${validationResult.errors.join(', ')}`);
      }

      // Verify signature
      const isValid = await this.verifySignature(signedData, signature, certificatePem, algorithm);
      logger.info('eID card signature verification completed', { verificationId, isValid });
      return isValid;
    } catch (error) {
      const errorMessage = `eID card signature verification failed: ${(error as Error).message}`;
      logger.error(errorMessage, { verificationId, error });
      throw error instanceof SignatureVerificationError
        ? error
        : new SignatureVerificationError(errorMessage);
    }
  }
}