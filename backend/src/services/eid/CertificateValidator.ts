import { logger } from '@root/utils/logger';
import { EID_CONFIG } from '@root/config/eid';
import { OCSP_REQUEST_TIMEOUT_MS, CRL_CACHE_TTL_MS } from '@utils/constants';
import fs from 'fs';
import path from 'path';
import axios, { AxiosError } from 'axios';
import { pki, util } from 'node-forge';
import * as pkijs from 'pkijs';
import { fromBER } from 'asn1js';
import validator from 'validator';
import {
  verifyCertificateChain,
  checkCertificateValidityPeriod,
  CertificateValidationError,
  getCertificateDistributionPoints,
  getOcspResponderUri,
  parseCertificate,
} from '@utils/certificateUtils';
import { Crl, fetchAndParseCrl } from '@utils/crlUtils';

/**
 * Result interface for certificate validation operations
 */
export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  timestamp: Date;
  validationMethod?: 'OCSP' | 'CRL' | 'CHAIN_ONLY';
}

/**
 * Configuration interface for the certificate validator
 */
export interface CertificateValidatorConfig {
  trustAnchors: string[];
  tr03124EacCaCert: string;
  enableOcspCheck: boolean;
  enableCrlCheck: boolean;
  ocspTimeout: number;
  crlCacheTtl: number;
  maxConcurrentValidations: number;
  maxRetries: number;
  retryDelay: number;
}

/**
 * Cache entry interface for CRL caching
 */
interface CrlCacheEntry {
  crl: Crl;
  expiry: number;
  fetchedAt: Date;
}

/**
 * Service for validating certificates in the eID ecosystem, ensuring TR-03124 compliance.
 * Supports chain verification, OCSP/CRL revocation checks, and secure configuration.
 */
export class CertificateValidator {
  private readonly trustAnchors: string[];
  private readonly tr03124EacCaCert: string;
  private readonly crlCache: Map<string, CrlCacheEntry>;
  private readonly config: CertificateValidatorConfig;
  private readonly activeValidations: Set<string> = new Set();

  constructor(customConfig?: Partial<CertificateValidatorConfig>) {
    try {
      this.trustAnchors = this.loadTrustAnchors();
      this.tr03124EacCaCert = this.loadTr03124EacCaCert();
      this.crlCache = new Map<string, CrlCacheEntry>();
      this.config = {
        trustAnchors: this.trustAnchors,
        tr03124EacCaCert: this.tr03124EacCaCert,
        enableOcspCheck: true,
        enableCrlCheck: true,
        ocspTimeout: OCSP_REQUEST_TIMEOUT_MS,
        crlCacheTtl: CRL_CACHE_TTL_MS,
        maxConcurrentValidations: 10,
        maxRetries: 3,
        retryDelay: 1000,
        ...customConfig,
      };

      this.validateConfiguration();
      logger.info('CertificateValidator initialized successfully', {
        trustAnchorsCount: this.trustAnchors.length,
        ocspEnabled: this.config.enableOcspCheck,
        crlEnabled: this.config.enableCrlCheck,
        maxConcurrentValidations: this.config.maxConcurrentValidations,
      });
    } catch (error) {
      const errorMessage = `Failed to initialize CertificateValidator: ${(error as Error).message}`;
      logger.error(errorMessage);
      throw new CertificateValidationError(errorMessage);
    }
  }

  /**
   * Loads trust anchor certificates from the file system with secure access checks.
   * @returns Array of trust anchor certificate PEM strings.
   * @private
   */
  private loadTrustAnchors(): string[] {
    const trustAnchorPaths = [
      EID_CONFIG.TRUST_ANCHOR_BVA_SERVER_CERT,
      EID_CONFIG.TRUST_ANCHOR_BVA_ECARD_PROFILES,
    ].filter(path => path); // Remove undefined/null paths

    const trustAnchors: string[] = [];

    for (const anchorPath of trustAnchorPaths) {
      try {
        const resolvedPath = path.resolve(anchorPath);
        // Check file accessibility
        fs.accessSync(resolvedPath, fs.constants.R_OK);
        const certContent = fs.readFileSync(resolvedPath, 'utf8').trim();
        if (!certContent) {
          throw new Error(`Trust anchor file is empty: ${resolvedPath}`);
        }
        // Basic PEM format validation
        if (!certContent.includes('-----BEGIN CERTIFICATE-----')) {
          throw new Error(`Invalid PEM format in trust anchor: ${resolvedPath}`);
        }
        trustAnchors.push(certContent);
        logger.debug(`Loaded trust anchor from: ${resolvedPath}`);
      } catch (error) {
        const errorMessage = `Failed to load trust anchor from ${anchorPath}: ${(error as Error).message}`;
        logger.error(errorMessage);
        throw new CertificateValidationError(errorMessage);
      }
    }

    if (trustAnchors.length === 0) {
      throw new CertificateValidationError('No trust anchors could be loaded');
    }

    return trustAnchors;
  }

  /**
   * Loads the TR-03124 EAC CA certificate with secure access checks.
   * @returns TR-03124 EAC CA certificate PEM string.
   * @private
   */
  private loadTr03124EacCaCert(): string {
    try {
      const certPath = path.resolve(EID_CONFIG.TR_03124_EAC_CA_CERT);
      fs.accessSync(certPath, fs.constants.R_OK);
      const certContent = fs.readFileSync(certPath, 'utf8').trim();
      if (!certContent) {
        throw new Error(`TR-03124 EAC CA certificate file is empty: ${certPath}`);
      }
      if (!certContent.includes('-----BEGIN CERTIFICATE-----')) {
        throw new Error(`Invalid PEM format in TR-03124 EAC CA certificate: ${certPath}`);
      }
      logger.debug(`Loaded TR-03124 EAC CA certificate from: ${certPath}`);
      return certContent;
    } catch (error) {
      const errorMessage = `Failed to load TR-03124 EAC CA certificate: ${(error as Error).message}`;
      logger.error(errorMessage);
      throw new CertificateValidationError(errorMessage);
    }
  }

  /**
   * Validates the configuration parameters.
   * @private
   */
  private validateConfiguration(): void {
    if (this.config.ocspTimeout <= 0) {
      throw new CertificateValidationError('OCSP timeout must be positive');
    }
    if (this.config.crlCacheTtl <= 0) {
      throw new CertificateValidationError('CRL cache TTL must be positive');
    }
    if (this.config.maxConcurrentValidations <= 0) {
      throw new CertificateValidationError('Max concurrent validations must be positive');
    }
    if (this.config.maxRetries < 0) {
      throw new CertificateValidationError('Max retries cannot be negative');
    }
    if (this.config.retryDelay < 0) {
      throw new CertificateValidationError('Retry delay cannot be negative');
    }
    if (!this.config.enableOcspCheck && !this.config.enableCrlCheck) {
      logger.warn('Both OCSP and CRL checks disabled; revocation checking will be skipped');
    }
  }

  /**
   * Validates a certificate against trust anchors and revocation lists.
   * @param certificatePem The certificate in PEM format.
   * @param options Optional validation options.
   * @returns Validation result with status, errors, and warnings.
   * @throws CertificateValidationError on critical errors.
   */
  public async validateCertificate(
    certificatePem: string,
    options: { skipRevocationCheck?: boolean } = {}
  ): Promise<ValidationResult> {
    const startTime = Date.now();
    const validationId = `cert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const result: ValidationResult = {
      isValid: false,
      errors: [],
      warnings: [],
      timestamp: new Date(),
    };

    // Input validation
    if (!certificatePem?.trim()) {
      result.errors.push('No certificate PEM provided');
      logger.warn('Certificate validation failed: No PEM provided', { validationId });
      return result;
    }
    if (!certificatePem.includes('-----BEGIN CERTIFICATE-----')) {
      result.errors.push('Invalid certificate PEM format');
      logger.warn('Certificate validation failed: Invalid PEM format', { validationId });
      return result;
    }

    // Check concurrent validation limit
    if (this.activeValidations.size >= this.config.maxConcurrentValidations) {
      result.errors.push('Maximum concurrent validations exceeded');
      logger.warn('Certificate validation rejected: Too many concurrent validations', {
        validationId,
        activeValidations: this.activeValidations.size,
      });
      return result;
    }

    this.activeValidations.add(validationId);

    try {
      logger.info('Starting certificate validation', { validationId });

      // Parse certificate
      let certificate: pki.Certificate;
      try {
        certificate = parseCertificate(certificatePem);
      } catch (parseError) {
        result.errors.push(`Failed to parse certificate: ${(parseError as Error).message}`);
        logger.error('Certificate parsing failed', { validationId, error: parseError });
        return result;
      }

      // 1. Verify certificate chain
      try {
        const isChainValid = verifyCertificateChain(certificatePem, [], this.trustAnchors);
        if (!isChainValid) {
          result.errors.push('Certificate chain validation failed');
          logger.warn('Certificate chain validation failed', { validationId, serialNumber: certificate.serialNumber });
        }
      } catch (chainError) {
        result.errors.push(`Certificate chain validation error: ${(chainError as Error).message}`);
        logger.error('Certificate chain validation error', { validationId, error: chainError });
      }

      // 2. Check validity period
      try {
        const isValidPeriod = checkCertificateValidityPeriod(certificatePem);
        if (!isValidPeriod) {
          result.errors.push('Certificate is outside its validity period');
          logger.warn('Certificate validity period check failed', { validationId, serialNumber: certificate.serialNumber });
        }
      } catch (periodError) {
        result.errors.push(`Certificate validity period check error: ${(periodError as Error).message}`);
        logger.error('Certificate validity period check error', { validationId, error: periodError });
      }

      // 3. Check revocation status
      if (!options.skipRevocationCheck) {
        try {
          const revocationResult = await this.checkRevocationStatus(certificatePem);
          if (!revocationResult.isValid) {
            result.errors.push(...revocationResult.errors);
            result.warnings.push(...revocationResult.warnings);
          } else {
            result.validationMethod = revocationResult.validationMethod;
            logger.debug(`Revocation check passed via ${revocationResult.validationMethod}`, { validationId });
          }
        } catch (revocationError) {
          result.errors.push(`Revocation status check error: ${(revocationError as Error).message}`);
          logger.error('Revocation status check error', { validationId, error: revocationError });
        }
      } else {
        result.warnings.push('Revocation status check was skipped');
        logger.debug('Revocation check skipped', { validationId });
      }

      // Determine overall validity
      result.isValid = result.errors.length === 0;

      const validationTime = Date.now() - startTime;
      logger.info('Certificate validation completed', {
        validationId,
        isValid: result.isValid,
        errorsCount: result.errors.length,
        warningsCount: result.warnings.length,
        validationTimeMs: validationTime,
        serialNumber: certificate.serialNumber,
      });

      return result;
    } catch (error) {
      const errorMessage = `Unexpected error during certificate validation: ${(error as Error).message}`;
      result.errors.push(errorMessage);
      logger.error(errorMessage, { validationId, error });
      return result;
    } finally {
      this.activeValidations.delete(validationId);
    }
  }

  /**
   * Checks revocation status using OCSP and CRL with retry logic.
   * @param certificatePem The certificate in PEM format.
   * @returns Validation result for revocation status.
   * @private
   */
  private async checkRevocationStatus(certificatePem: string): Promise<ValidationResult> {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
      timestamp: new Date(),
    };

    try {
      const certificate = parseCertificate(certificatePem);

      // Try OCSP first
      if (this.config.enableOcspCheck) {
        const ocspUri = getOcspResponderUri(certificate);
        if (ocspUri && validator.isURL(ocspUri)) {
          logger.debug(`Attempting OCSP check`, { ocspUri });
          try {
            const ocspResult = await this.checkOcsp(certificatePem, ocspUri);
            if (ocspResult) {
              result.validationMethod = 'OCSP';
              logger.info('Certificate revocation status confirmed via OCSP', { serialNumber: certificate.serialNumber });
              return result;
            }
            result.errors.push('Certificate is revoked according to OCSP');
            result.isValid = false;
            return result;
          } catch (ocspError) {
            result.warnings.push(`OCSP check failed: ${(ocspError as Error).message}`);
            logger.warn('OCSP check failed', { error: ocspError, serialNumber: certificate.serialNumber });
          }
        } else {
          result.warnings.push('No valid OCSP responder URI found in certificate');
          logger.debug('No OCSP URI found', { serialNumber: certificate.serialNumber });
        }
      }

      // Fallback to CRL
      if (this.config.enableCrlCheck) {
        const crlDistributionPoints = getCertificateDistributionPoints(certificate).filter(dp => validator.isURL(dp));
        if (crlDistributionPoints.length > 0) {
          logger.debug(`Attempting CRL check`, { distributionPoints: crlDistributionPoints });
          try {
            const crlResult = await this.checkCrl(certificatePem, crlDistributionPoints);
            if (crlResult) {
              result.validationMethod = 'CRL';
              logger.info('Certificate revocation status confirmed via CRL', { serialNumber: certificate.serialNumber });
              return result;
            }
            result.errors.push('Certificate is revoked according to CRL');
            result.isValid = false;
            return result;
          } catch (crlError) {
            result.warnings.push(`CRL check failed: ${(crlError as Error).message}`);
            logger.warn('CRL check failed', { error: crlError, serialNumber: certificate.serialNumber });
          }
        } else {
          result.warnings.push('No valid CRL distribution points found in certificate');
          logger.debug('No CRL distribution points found', { serialNumber: certificate.serialNumber });
        }
      }

      result.warnings.push('Could not determine revocation status via OCSP or CRL');
      result.validationMethod = 'CHAIN_ONLY';
      logger.warn('Revocation status indeterminate', { serialNumber: certificate.serialNumber });
      return result;
    } catch (error) {
      result.errors.push(`Revocation status check failed: ${(error as Error).message}`);
      result.isValid = false;
      logger.error('Revocation status check failed', { error });
      return result;
    }
  }

  /**
   * Performs OCSP check with retry logic.
   * @param certificatePem The certificate in PEM format.
   * @param ocspUri The OCSP responder URI.
   * @returns True if certificate is not revoked, false otherwise.
   * @private
   */
  private async checkOcsp(certificatePem: string, ocspUri: string): Promise<boolean> {
    if (!ocspUri || !validator.isURL(ocspUri)) {
      throw new CertificateValidationError('Invalid or missing OCSP responder URI');
    }

    logger.debug(`Performing OCSP check`, { ocspUri });

    for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
      try {
        const ocspRequest = await this.buildOcspRequest(certificatePem);
        const response = await axios.post(ocspUri, ocspRequest, {
          headers: {
            'Content-Type': 'application/ocsp-request',
            'User-Agent': 'eID-CertificateValidator/1.0',
          },
          responseType: 'arraybuffer',
          timeout: this.config.ocspTimeout,
          validateStatus: status => status < 500,
        });

        if (response.status !== 200) {
          throw new Error(`OCSP responder returned status ${response.status}`);
        }

        const isCertificateGood = await this.parseOcspResponse(response.data);
        logger.info(`OCSP check successful`, { attempt, isCertificateGood });
        return isCertificateGood;
      } catch (error) {
        const errorMessage = axios.isAxiosError(error)
          ? error.code === 'ECONNABORTED'
            ? `OCSP check timed out after ${this.config.ocspTimeout}ms`
            : error.response
            ? `OCSP responder error: HTTP ${error.response.status}`
            : `Network error: ${error.message}`
          : `OCSP check error: ${(error as Error).message}`;
        logger.warn(`OCSP check attempt ${attempt} failed`, { error: errorMessage });
        if (attempt === this.config.maxRetries) {
          throw new CertificateValidationError(errorMessage);
        }
        await new Promise(resolve => setTimeout(resolve, this.config.retryDelay));
      }
    }

    throw new CertificateValidationError('OCSP check failed after maximum retries');
  }

  /**
   * Performs CRL check with caching and retry logic.
   * @param certificatePem The certificate in PEM format.
   * @param crlDistributionPoints Array of CRL distribution point URIs.
   * @returns True if certificate is not revoked, false otherwise.
   * @private
   */
  private async checkCrl(certificatePem: string, crlDistributionPoints: string[]): Promise<boolean> {
    logger.debug(`Initiating CRL check`, { distributionPointsCount: crlDistributionPoints.length });

    try {
      const certificate = parseCertificate(certificatePem);
      const serialNumber = certificate.serialNumber;
      this.cleanupExpiredCrlCache();

      for (const url of crlDistributionPoints) {
        if (!validator.isURL(url)) {
          logger.warn(`Invalid CRL distribution point URL: ${url}`);
          continue;
        }

        let crl: Crl | null = null;
        const cachedCrlEntry = this.crlCache.get(url);
        const now = Date.now();

        if (cachedCrlEntry && cachedCrlEntry.expiry > now) {
          crl = cachedCrlEntry.crl;
          logger.debug(`Using cached CRL`, { url, cachedAt: cachedCrlEntry.fetchedAt });
        } else {
          for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
            try {
              crl = await fetchAndParseCrl(url);
              if (crl) {
                this.crlCache.set(url, {
                  crl,
                  expiry: now + this.config.crlCacheTtl,
                  fetchedAt: new Date(),
                });
                logger.info(`Successfully fetched and cached CRL`, { url, attempt });
                break;
              }
            } catch (fetchError) {
              logger.warn(`CRL fetch attempt ${attempt} failed`, { url, error: (fetchError as Error).message });
              if (attempt === this.config.maxRetries) {
                logger.error(`CRL fetch failed after ${this.config.maxRetries} attempts`, { url });
                continue;
              }
              await new Promise(resolve => setTimeout(resolve, this.config.retryDelay));
            }
          }
        }

        if (crl && crl.isRevoked(serialNumber)) {
          logger.warn(`Certificate is revoked`, { serialNumber, crlUrl: url });
          return false;
        }
      }

      logger.info(`Certificate is not revoked according to CRLs`, { serialNumber });
      return true;
    } catch (error) {
      logger.error(`CRL check failed`, { error: (error as Error).message });
      throw new CertificateValidationError(`CRL check failed: ${(error as Error).message}`);
    }
  }

  /**
   * Builds an OCSP request using pkijs.
   * @param certificatePem The certificate in PEM format.
   * @returns OCSP request as a Buffer.
   * @private
   */
  private async buildOcspRequest(certificatePem: string): Promise<Buffer> {
    if (!certificatePem?.trim()) {
      throw new CertificateValidationError('No certificate PEM provided for OCSP request');
    }

    try {
      const certificate = parseCertificate(certificatePem);
      const issuerCert = parseCertificate(this.trustAnchors[0]); // Use first trust anchor as issuer
      const ocspReq = new pkijs.OCSP.OCSPRequest();
      const certId = new pkijs.OCSP.CertID({
        issuerNameHash: await pkijs.Certificate.prototype.getIssuerNameHash.call(certificate),
        issuerKeyHash: await pkijs.Certificate.prototype.getIssuerKeyHash.call(certificate),
        serialNumber: new pkijs.ASN1.Integer({ value: parseInt(certificate.serialNumber, 16) }),
      });

      ocspReq.tbsRequest.requestList.push(new pkijs.OCSP.Request({ reqCert: certId }));
      const ocspRequestData = ocspReq.toSchema().toBER(false);
      logger.debug(`Built OCSP request`, { serialNumber: certificate.serialNumber });
      return Buffer.from(ocspRequestData);
    } catch (error) {
      const errorMessage = `Failed to build OCSP request: ${(error as Error).message}`;
      logger.error(errorMessage);
      throw new CertificateValidationError(errorMessage);
    }
  }

  /**
   * Parses and verifies an OCSP response using pkijs.
   * @param ocspResponseBuffer The OCSP response as a Buffer.
   * @returns True if certificate status is 'good', false otherwise.
   * @private
   */
  private async parseOcspResponse(ocspResponseBuffer: Buffer): Promise<boolean> {
    if (!ocspResponseBuffer || ocspResponseBuffer.length === 0) {
      throw new CertificateValidationError('Empty OCSP response received');
    }

    try {
      const bufferSlice = ocspResponseBuffer.buffer.slice(ocspResponseBuffer.byteOffset, ocspResponseBuffer.byteOffset + ocspResponseBuffer.byteLength);
      const arrayBuffer = new Uint8Array(bufferSlice).slice().buffer;
      const asn1 = fromBER(arrayBuffer);
      if (asn1.offset === -1) {
        throw new CertificateValidationError('Invalid OCSP response format');
      }

      const ocspResponse = new pkijs.OCSP.OCSPResponse({ schema: asn1.result });
      if (ocspResponse.responseStatus.valueBlock.valueDec !== 0) {
        throw new CertificateValidationError(`OCSP response status: ${ocspResponse.responseStatus.valueBlock.valueDec}`);
      }

      if (!ocspResponse.responseBytes) {
        throw new CertificateValidationError('No response bytes in OCSP response');
      }

      const basicOCSPResponse = new pkijs.OCSP.BasicOCSPResponse({
        schema: fromBER(ocspResponse.responseBytes.response.value).result,
      });

      // Verify response signature
      const isSignatureValid = await basicOCSPResponse.verify({
        trustedCerts: this.trustAnchors.map(pem => {
          const binaryString: string = util.createBuffer(pem).data;
          const arrayBuffer = Buffer.from(binaryString, 'binary').buffer;
          return pkijs.Certificate.fromBER(arrayBuffer);
        }),
      });
      if (!isSignatureValid) {
        throw new CertificateValidationError('OCSP response signature verification failed');
      }

      const response = basicOCSPResponse.tbsResponseData.responses[0];
      const certStatus = response.certStatus;

      const isGood = certStatus && certStatus.value === 'good';
      logger.info(`OCSP response parsed`, { isCertificateGood: isGood });
      return isGood;
    } catch (error) {
      const errorMessage = `Failed to parse OCSP response: ${(error as Error).message}`;
      logger.error(errorMessage);
      throw new CertificateValidationError(errorMessage);
    }
  }

  /**
   * Validates a certificate against TR-03124 EAC CA requirements.
   * @param certificatePem The certificate in PEM format.
   * @param options Optional validation options.
   * @returns Validation result.
   * @throws CertificateValidationError on critical errors.
   */
  public async validateTr03124EacCertificate(
    certificatePem: string,
    options: { skipRevocationCheck?: boolean } = {}
  ): Promise<ValidationResult> {
    const result: ValidationResult = {
      isValid: false,
      errors: [],
      warnings: [],
      timestamp: new Date(),
    };

    if (!certificatePem?.trim() || !certificatePem.includes('-----BEGIN CERTIFICATE-----')) {
      result.errors.push('Invalid or missing certificate PEM for TR-03124 EAC validation');
      logger.warn('TR-03124 EAC validation failed: Invalid PEM');
      return result;
    }

    try {
      logger.info('Starting TR-03124 EAC certificate validation');

      let certificate: pki.Certificate;
      try {
        certificate = parseCertificate(certificatePem);
      } catch (parseError) {
        result.errors.push(`Failed to parse certificate: ${(parseError as Error).message}`);
        logger.error('Certificate parsing failed', { error: parseError });
        return result;
      }

      // 1. Verify chain against TR-03124 EAC CA
      try {
        const isEacChainValid = verifyCertificateChain(certificatePem, [], [this.tr03124EacCaCert]);
        if (!isEacChainValid) {
          result.errors.push('TR-03124 EAC certificate chain validation failed');
          logger.warn('TR-03124 EAC chain validation failed', { serialNumber: certificate.serialNumber });
        }
      } catch (chainError) {
        result.errors.push(`TR-03124 EAC chain validation error: ${(chainError as Error).message}`);
        logger.error('TR-03124 EAC chain validation error', { error: chainError });
      }

      // 2. Check validity period
      try {
        const isValidPeriod = checkCertificateValidityPeriod(certificatePem);
        if (!isValidPeriod) {
          result.errors.push('TR-03124 EAC certificate is outside its validity period');
          logger.warn('TR-03124 EAC validity period check failed', { serialNumber: certificate.serialNumber });
        }
      } catch (periodError) {
        result.errors.push(`TR-03124 EAC validity period error: ${(periodError as Error).message}`);
        logger.error('TR-03124 EAC validity period error', { error: periodError });
      }

      // 3. Validate TR-03124 extensions
      try {
        const tr03124ValidationResult = this.validateTr03124Extensions(certificate);
        if (!tr03124ValidationResult.isValid) {
          result.errors.push(...tr03124ValidationResult.errors);
          result.warnings.push(...tr03124ValidationResult.warnings);
        }
      } catch (extensionError) {
        result.errors.push(`TR-03124 extension validation error: ${(extensionError as Error).message}`);
        logger.error('TR-03124 extension validation error', { error: extensionError });
      }

      // 4. Check revocation status
      if (!options.skipRevocationCheck) {
        try {
          const revocationResult = await this.checkRevocationStatus(certificatePem);
          if (!revocationResult.isValid) {
            result.errors.push(...revocationResult.errors);
            result.warnings.push(...revocationResult.warnings);
          } else {
            result.validationMethod = revocationResult.validationMethod;
            logger.debug(`TR-03124 revocation check passed via ${revocationResult.validationMethod}`, {
              serialNumber: certificate.serialNumber,
            });
          }
        } catch (revocationError) {
          result.errors.push(`TR-03124 EAC revocation check error: ${(revocationError as Error).message}`);
          logger.error('TR-03124 EAC revocation check error', { error: revocationError });
        }
      }

      result.isValid = result.errors.length === 0;
      logger.info('TR-03124 EAC certificate validation completed', {
        isValid: result.isValid,
        errorsCount: result.errors.length,
        warningsCount: result.warnings.length,
        serialNumber: certificate.serialNumber,
      });

      return result;
    } catch (error) {
      const errorMessage = `Unexpected error during TR-03124 EAC validation: ${(error as Error).message}`;
      result.errors.push(errorMessage);
      logger.error(errorMessage);
      return result;
    }
  }

  /**
   * Validates TR-03124 specific certificate extensions and constraints.
   * @param certificate The parsed certificate.
   * @returns Validation result for TR-03124 compliance.
   * @private
   */
  private validateTr03124Extensions(certificate: pki.Certificate): ValidationResult {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
      timestamp: new Date(),
    };

    try {
      const extensions = certificate.extensions;
      if (!extensions || extensions.length === 0) {
        result.errors.push('No certificate extensions found');
        result.isValid = false;
        logger.warn('No extensions found for TR-03124 validation', { serialNumber: certificate.serialNumber });
        return result;
      }

      // Check Key Usage (TR-03124 requires specific key usage)
      const keyUsageExt = extensions.find(ext => ext.oid === '2.5.29.15');
      if (!keyUsageExt) {
        result.errors.push('Missing KeyUsage extension');
        result.isValid = false;
      } else {
        // Assuming keyUsage is parsed as a bit string
        const keyUsage = keyUsageExt.value; // Simplified; parse bit string in production
        if (!keyUsage.includes('digitalSignature') && !keyUsage.includes('keyAgreement')) {
          result.errors.push('Invalid KeyUsage for TR-03124: digitalSignature or keyAgreement required');
          result.isValid = false;
        }
      }

      // Check Extended Key Usage (TR-03124 EAC-specific OIDs)
      const extKeyUsageExt = extensions.find(ext => ext.oid === '2.5.29.37');
      if (!extKeyUsageExt) {
        result.errors.push('Missing ExtendedKeyUsage extension');
        result.isValid = false;
      } else {
        const eacOids = ['1.3.36.8.3.1', '1.3.36.8.3.2']; // Example EAC OIDs
        const extKeyUsages = extKeyUsageExt.value; // Simplified; parse OIDs in production
        if (!eacOids.some(oid => extKeyUsages.includes(oid))) {
          result.errors.push('Missing TR-03124 EAC-specific ExtendedKeyUsage');
          result.isValid = false;
        }
      }

      // Check Certificate Policies
      const certPoliciesExt = extensions.find(ext => ext.oid === '2.5.29.32');
      if (!certPoliciesExt) {
        result.warnings.push('Missing CertificatePolicies extension');
      } else {
        const policies = certPoliciesExt.value; // Simplified; parse policy OIDs
        const tr03124Policy = '1.3.36.8.1.1'; // Example TR-03124 policy OID
        if (!policies.includes(tr03124Policy)) {
          result.warnings.push('Missing TR-03124-specific certificate policy');
        }
      }

      // Check Basic Constraints
      const basicConstraintsExt = extensions.find(ext => ext.oid === '2.5.29.19');
      // If the basicConstraints extension exists and indicates it's a CA, then it's an error for TR-03124 EAC
      if (basicConstraintsExt && typeof basicConstraintsExt.value === 'object' && (basicConstraintsExt.value as any).cA === true) {
        result.errors.push('TR-03124 EAC certificate must not be a CA certificate');
        result.isValid = false;
      }

      logger.debug('TR-03124 extension validation completed', {
        isValid: result.isValid,
        serialNumber: certificate.serialNumber,
      });

      return result;
    } catch (error) {
      result.errors.push(`TR-03124 extension validation failed: ${(error as Error).message}`);
      result.isValid = false;
      logger.error('TR-03124 extension validation failed', { error, serialNumber: certificate.serialNumber });
      return result;
    }
  }

  /**
   * Cleans up expired CRL cache entries.
   * @private
   */
  private cleanupExpiredCrlCache(): void {
    const now = Date.now();
    let removedCount = 0;

    for (const [url, entry] of this.crlCache.entries()) {
      if (entry.expiry <= now) {
        this.crlCache.delete(url);
        removedCount++;
      }
    }

    if (removedCount > 0) {
      logger.debug(`Cleaned up ${removedCount} expired CRL cache entries`);
    }
  }

  /**
   * Retrieves cache statistics for monitoring.
   * @returns Cache statistics including size and active validations.
   */
  public getCacheStatistics(): {
    crlCacheSize: number;
    activeValidations: number;
    cacheEntries: Array<{ url: string; fetchedAt: Date; expiresAt: Date }>;
  } {
    const cacheEntries = Array.from(this.crlCache.entries()).map(([url, entry]) => ({
      url,
      fetchedAt: entry.fetchedAt,
      expiresAt: new Date(entry.expiry),
    }));

    return {
      crlCacheSize: this.crlCache.size,
      activeValidations: this.activeValidations.size,
      cacheEntries,
    };
  }

  /**
   * Clears all cached CRL data.
   */
  public clearCrlCache(): void {
    const clearedCount = this.crlCache.size;
    this.crlCache.clear();
    logger.info(`Manually cleared ${clearedCount} CRL cache entries`);
  }

  /**
   * Gracefully shuts down the validator.
   */
  public async shutdown(): Promise<void> {
    logger.info('Shutting down CertificateValidator');

    const maxWaitTime = 30000;
    const startTime = Date.now();

    while (this.activeValidations.size > 0 && Date.now() - startTime < maxWaitTime) {
      logger.debug(`Waiting for ${this.activeValidations.size} active validations to complete`);
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    if (this.activeValidations.size > 0) {
      logger.warn(`Shutdown timeout: ${this.activeValidations.size} validations still active`);
    }

    this.clearCrlCache();
    this.activeValidations.clear();
    logger.info('CertificateValidator shutdown complete');
  }
}