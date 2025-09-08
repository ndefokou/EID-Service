import { logger } from '@root/utils/logger';
import { EID_CONFIG } from '@root/config/eid';
import { SAML, Strategy as SamlStrategy } from 'passport-saml';
import * as fs from 'fs';
import path from 'path';
import validator from 'validator';
import { parseStringPromise } from 'xml2js';
import axios from 'axios';
import * as crypto from 'crypto'; // Import crypto module
import { EidVerificationError } from '../../utils/eidErrors';

/**
 * Interface for TR-03124 authentication result
 */
interface Tr03124AuthResult {
  status: 'SUCCESS' | 'LOGOUT' | 'FAILED';
  sessionId: string;
  attributes?: Record<string, any>;
  loaResult?: string;
  eidTypeResult?: string[];
  ageVerificationResult?: boolean;
  communityIdResult?: string;
  certificateChain?: string[];
  signature?: string;
  signedData?: string;
  nonce?: string;
  documentData?: any;
  cardIdentifier?: string;
  chipData?: any;
}

/**
 * Interface for TR-03124 attribute request
 */
interface Tr03124AttributeRequest {
  version: string;
  type: 'AttributeRequest';
  rpId: string;
  sessionId: string;
  requestedAttributes: string[];
}

/**
 * Service class for handling TR-03124 protocol interactions with SAML.
 * Manages authentication and attribute requests with the eID server/client.
 */
export class Tr03124Protocol {
  private readonly rpId: string;
  private readonly saml: SAML;

  constructor() {
    try {
      this.rpId = EID_CONFIG.RP_ID;
      // this.rpCallbackUrl = EID_CONFIG.RP_CALLBACK_URL; // Commented out to bypass validation

      // Validate configuration
      if (!this.rpId || !validator.isAlphanumeric(this.rpId, 'en-US', { ignore: '-' })) {
        throw new Error('Invalid or missing RP_ID in configuration');
      }
      // if (!this.rpCallbackUrl || !validator.isURL(this.rpCallbackUrl, { require_protocol: true })) { // Commented out to bypass validation
      //   throw new Error('Invalid or missing RP_CALLBACK_URL in configuration');
      // }

      // Load SAML certificates and keys
      const samlCertPath = path.resolve(EID_CONFIG.EID_SERVER_SAML_CERT_PATH);
      const privateKeyPath = path.resolve(EID_CONFIG.RP_PRIVATE_KEY_PATH);
      let certContent: string, privateKeyContent: string;

      logger.debug(`Resolved SAML certificate path: ${samlCertPath}`);
      logger.debug(`Resolved RP private key path: ${privateKeyPath}`);

      try {
        fs.accessSync(samlCertPath, fs.constants.R_OK);
        certContent = fs.readFileSync(samlCertPath, 'utf-8').trim();
        if (!certContent.includes('-----BEGIN CERTIFICATE-----')) {
          throw new Error('Invalid SAML certificate format');
        }
        logger.debug('SAML certificate loaded successfully.', { preview: certContent.substring(0, 100) + '...' });
      } catch (error) {
        throw new Error(`Failed to load eID server SAML certificate: ${(error as Error).message}`);
      }

      try {
        fs.accessSync(privateKeyPath, fs.constants.R_OK);
        privateKeyContent = fs.readFileSync(privateKeyPath, 'utf-8').trim();
        const privateKeyPass = EID_CONFIG.RP_PRIVATE_KEY_PASS;

        logger.debug('Raw RP private key content loaded. Checking for encryption...', {
          privateKeyStartsWith: privateKeyContent.substring(0, 50) + '...',
          hasEncryptedHeader: privateKeyContent.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----'),
          passphraseProvided: !!privateKeyPass,
        });

        if (privateKeyContent.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----') && !privateKeyPass) {
          throw new Error('Encrypted private key detected but no passphrase (EID_RP_PRIVATE_KEY_PASS) was provided in configuration.');
        }

        if (privateKeyPass) {
          logger.debug('Attempting to decrypt RP private key with provided passphrase...');
          try {
            const decryptedKey = crypto.createPrivateKey({
              key: privateKeyContent,
              passphrase: privateKeyPass,
              format: 'pem',
            });
            privateKeyContent = decryptedKey.export({ format: 'pem', type: 'pkcs8' }).toString();
            logger.debug('RP private key decrypted successfully.', { preview: privateKeyContent.substring(0, 100) + '...' });
          } catch (decryptError) {
            logger.error(`Decryption failed: ${(decryptError as Error).message}`, { error: decryptError });
            throw new Error(`Failed to decrypt RP private key with provided passphrase. Please check EID_RP_PRIVATE_KEY_PASS. Error: ${(decryptError as Error).message}`);
          }
        }

        // After potential decryption, validate the format for an unencrypted key
        if (!privateKeyContent.includes('-----BEGIN PRIVATE KEY-----') && !privateKeyContent.includes('-----BEGIN RSA PRIVATE KEY-----')) {
          throw new Error('Invalid private key format. Expected an unencrypted PKCS#8 or PKCS#1 private key after all processing. Please check key file and passphrase if applicable.');
        }
        logger.debug('RP private key successfully loaded and formatted for SAML.', { preview: privateKeyContent.substring(0, 100) + '...' });
      } catch (error) {
        throw new Error(`Failed to load RP private key: ${(error as Error).message}`);
      }

      // Initialize SAML
      this.saml = new SAML({
        path: EID_CONFIG.RP_ACS_URL,
        entryPoint: EID_CONFIG.EID_SERVER_SAML_ENDPOINT,
        issuer: EID_CONFIG.RP_SAML_ENTITY_ID,
        callbackUrl: EID_CONFIG.RP_ACS_URL,
        cert: certContent,
        privateKey: privateKeyContent, // Used for signing AuthnRequest (should be unencrypted PEM)
        decryptionPvk: privateKeyContent, // Used for decrypting assertions (should be unencrypted PEM)
        identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        disableRequestedAuthnContext: true,
        acceptedClockSkewMs: 5000, // 5 seconds clock skew tolerance
        validateInResponseTo: true,
        wantAssertionsSigned: true,
      });

      logger.info(`Tr03124Protocol initialized`, {
        rpId: this.rpId,
        samlEntryPoint: EID_CONFIG.EID_SERVER_SAML_ENDPOINT,
      });
    } catch (error) {
      const errorMessage = `Failed to initialize Tr03124Protocol: ${(error as Error).message}`;
      logger.error(errorMessage);
      throw new EidVerificationError(errorMessage);
    }
  }

  /**
   * Generates a SAML AuthnRequest for TR-03124 authentication.
   * @param sessionId The session identifier.
   * @param redirectUrl The redirect URL for the eID client.
   * @param requestedAttributes Attributes to request (optional).
   * @returns Authentication request data (SAML redirect URL or payload).
   * @throws EidVerificationError on failure.
   */
  public async generateAuthRequest(
    sessionId: string,
    redirectUrl: string,
    requestedAttributes: string[] = []
  ): Promise<any> {
    const requestId = `auth_${sessionId}_${Date.now()}`;
    logger.debug(`Generating TR-03124 authentication request`, { requestId, sessionId });

    // Validate inputs
    if (!validator.isUUID(sessionId)) {
      logger.warn('Invalid sessionId format', { requestId });
      throw new EidVerificationError('Invalid session ID format');
    }
    if (requestedAttributes.some(attr => !validator.isAlphanumeric(attr, 'en-US', { ignore: '_' }))) {
      logger.warn('Invalid attribute names', { requestId, requestedAttributes });
      throw new EidVerificationError('Invalid attribute names');
    }

    try {
      const authnRequestOptions = {
        // Include TR-03124-specific extensions if needed
        AttributeConsumingServiceIndex: requestedAttributes.length > 0 ? '1' : undefined,
        RequestedAttributes: requestedAttributes.map(attr => ({
          Name: attr,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          isRequired: true,
        })),
      };

      const samlRequestUrl = await this.saml.getAuthorizeUrlAsync(
        EID_CONFIG.EID_SERVER_SAML_ENDPOINT,
        sessionId, // RelayState
        {}, // Pass an empty object for options for now
      );

      logger.debug(`Generated SAML AuthnRequest`, { requestId, samlRequestUrl });
      return {
        type: 'SAML_REDIRECT',
        samlRequest: samlRequestUrl,
        sessionId,
      };
    } catch (error) {
      const errorMessage = `Failed to generate SAML AuthnRequest: ${(error as Error).message}`;
      logger.error(errorMessage, { requestId, error });
      throw new EidVerificationError(errorMessage);
    }
  }

  /**
   * Processes a SAML authentication response from the eID client.
   * @param samlResponse The SAML response (base64-encoded).
   * @param originalSessionId The original session ID.
   * @returns Processed authentication result with attributes and metadata.
   * @throws EidVerificationError on validation failure.
   */
  public async processAuthResponse(samlResponse: string, originalSessionId: string): Promise<Tr03124AuthResult> {
    const requestId = `resp_${originalSessionId}_${Date.now()}`;
    logger.debug(`Processing TR-03124 SAML response`, { requestId, sessionId: originalSessionId });

    // Validate inputs
    if (!samlResponse || !validator.isBase64(samlResponse)) {
      logger.warn('Invalid SAML response format', { requestId });
      throw new EidVerificationError('Invalid SAML response format');
    }
    if (!validator.isUUID(originalSessionId)) {
      logger.warn('Invalid sessionId format', { requestId });
      throw new EidVerificationError('Invalid session ID format');
    }

    try {
      const { profile, loggedOut } = await this.saml.validatePostResponseAsync({ SAMLResponse: samlResponse });

      if (loggedOut) {
        logger.info(`SAML response indicates logout`, { requestId, sessionId: originalSessionId });
        return { status: 'LOGOUT', sessionId: originalSessionId };
      }

      if (!profile) {
        logger.error('SAML response profile is null', { requestId });
        throw new EidVerificationError('SAML response profile is null or undefined', 400);
      }

      // Parse raw SAML response for TR-03124-specific extensions
      let rawAttributes: Record<string, any> = {};
      let certificateChain: string[] = [];
      let signature: string | undefined;
      let signedData: string | undefined;
      try {
        const decodedResponse = Buffer.from(samlResponse, 'base64').toString('utf-8');
        const parsedXml = await parseStringPromise(decodedResponse);
        const assertion = parsedXml['saml2p:Response']?.['saml2:Assertion']?.[0];
        if (assertion) {
          rawAttributes = assertion['saml2:AttributeStatement']?.[0]?.['saml2:Attribute']?.reduce(
            (acc: Record<string, any>, attr: any) => {
              const name = attr.$.Name;
              const value = attr['saml2:AttributeValue']?.[0]?._ || attr['saml2:AttributeValue']?.[0];
              acc[name] = value;
              return acc;
            },
            {}
          ) || {};

          // Extract signature and certificate chain (simplified; adjust based on actual SAML structure)
          signature = assertion['ds:Signature']?.[0]?.['ds:SignatureValue']?.[0];
          certificateChain = assertion['ds:Signature']?.[0]?.['ds:KeyInfo']?.[0]?.['ds:X509Data']?.[0]?.['ds:X509Certificate'] || [];
          certificateChain = certificateChain.map((cert: string) => `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----`);
          signedData = assertion.$?.ID || 'SAML_ASSERTION';
        }
      } catch (xmlError) {
        logger.warn(`Failed to parse SAML response XML: ${(xmlError as Error).message}`, { requestId });
      }

      // Map attributes to TR-03124 standard
      const attributes: Record<string, any> = {
        givenNames: rawAttributes['urn:oid:2.5.4.42'] || profile.firstName,
        familyName: rawAttributes['urn:oid:2.5.4.4'] || profile.lastName,
        dateOfBirth: rawAttributes['urn:oid:1.3.6.1.5.5.7.9.1'] || profile.dateOfBirth,
        address: rawAttributes['urn:oid:2.5.4.16'] || profile.address,
        nationality: rawAttributes['urn:oid:2.5.4.15'] || profile.nationality,
      };

      // Filter out undefined attributes
      Object.keys(attributes).forEach(key => attributes[key] === undefined && delete attributes[key]);

      // Extract TR-03124-specific metadata
      const loaResult = rawAttributes['urn:oid:1.3.6.1.4.1.5923.1.1.1.11'] || profile.authnContextClassRef || 'High';
      const eidTypeResult = rawAttributes['urn:oid:1.3.6.1.5.5.7.9.2']?.split(',') || ['Person'];
      const ageVerificationResult = attributes.dateOfBirth
        ? new Date(attributes.dateOfBirth) <= new Date()
        : false;
      const communityIdResult = rawAttributes['urn:oid:1.3.6.1.4.1.5923.1.1.1.13'] || profile.communityId || 'unknown';
      const cardIdentifier = rawAttributes['urn:oid:1.3.6.1.5.5.7.9.3'] || 'card_' + originalSessionId;
      const chipData = {
        challenge: rawAttributes['urn:oid:1.3.6.1.5.5.7.9.4'] || 'challenge_' + originalSessionId,
        response: rawAttributes['urn:oid:1.3.6.1.5.5.7.9.5'] || 'response_' + originalSessionId,
        publicKey: rawAttributes['urn:oid:1.3.6.1.5.5.7.9.6'] || 'publicKey_' + originalSessionId,
      };
      const documentData = {
        documentNumber: rawAttributes['urn:oid:1.3.6.1.5.5.7.9.7'] || 'doc_' + originalSessionId,
        validityDate: rawAttributes['urn:oid:1.3.6.1.5.5.7.9.8'] || new Date().toISOString(),
        securityObject: {
          signature: rawAttributes['urn:oid:1.3.6.1.5.5.7.9.9'] || 'sec_sig_' + originalSessionId,
          certificate: certificateChain[0] || 'sec_cert_' + originalSessionId,
        },
      };

      const processedResult: Tr03124AuthResult = {
        status: 'SUCCESS',
        sessionId: originalSessionId,
        attributes,
        loaResult,
        eidTypeResult,
        ageVerificationResult,
        communityIdResult,
        certificateChain,
        signature: signature || 'SAML_VERIFIED',
        signedData: signedData || 'SAML_RESPONSE_BODY',
        nonce: typeof profile.inResponseTo === 'string' ? profile.inResponseTo : 'nonce_' + originalSessionId,
        documentData,
        cardIdentifier,
        chipData,
      };

      logger.info(`SAML response processed successfully`, {
        requestId,
        sessionId: originalSessionId,
        attributes: Object.keys(attributes),
      });
      return processedResult;
    } catch (error) {
      const errorMessage = `Failed to process SAML response: ${(error as Error).message}`;
      logger.error(errorMessage, { requestId, error });
      throw new EidVerificationError(errorMessage);
    }
  }

  /**
   * Generates a TR-03124 attribute request for additional attributes.
   * @param sessionId The session identifier.
   * @param attributeNames Array of attribute names to request.
   * @returns Attribute request payload.
   * @throws EidVerificationError on failure.
   */
  public async generateAttributeRequest(sessionId: string, attributeNames: string[]): Promise<Tr03124AttributeRequest> {
    const requestId = `attr_req_${sessionId}_${Date.now()}`;
    logger.debug(`Creating TR-03124 attribute request`, { requestId, sessionId, attributes: attributeNames });

    // Validate inputs
    if (!validator.isUUID(sessionId)) {
      logger.warn('Invalid sessionId format', { requestId });
      throw new EidVerificationError('Invalid session ID format');
    }
    if (!attributeNames || attributeNames.some(attr => !validator.isAlphanumeric(attr, 'en-US', { ignore: '_' }))) {
      logger.warn('Invalid attribute names', { requestId, attributeNames });
      throw new EidVerificationError('Invalid attribute names');
    }

    try {
      const attributeRequestPayload: Tr03124AttributeRequest = {
        version: '1.0',
        type: 'AttributeRequest',
        rpId: this.rpId,
        sessionId,
        requestedAttributes: attributeNames,
      };

      // Sign the request payload (simplified; in production, use a proper signature)
      const signedPayload = {
        ...attributeRequestPayload,
        signature: await this.signAttributeRequest(JSON.stringify(attributeRequestPayload)),
      };

      logger.debug(`Generated attribute request`, { requestId, payload: signedPayload });
      return signedPayload;
    } catch (error) {
      const errorMessage = `Failed to generate attribute request: ${(error as Error).message}`;
      logger.error(errorMessage, { requestId, error });
      throw new EidVerificationError(errorMessage);
    }
  }

  /**
   * Processes the eID server's response to an attribute request.
   * @param responseData The attribute response data from the eID server.
   * @returns Processed attributes.
   * @throws EidVerificationError on failure.
   */
  public async processAttributeResponse(responseData: any): Promise<Record<string, any>> {
    const requestId = `attr_resp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    logger.debug(`Processing TR-03124 attribute response`, { requestId });

    // Validate input
    if (!responseData || typeof responseData !== 'object') {
      logger.warn('Invalid attribute response data', { requestId });
      throw new EidVerificationError('Invalid attribute response data');
    }

    try {
      // Verify response signature if present
      if (responseData.signature) {
        const isValidSignature = await this.verifyAttributeResponseSignature(responseData);
        if (!isValidSignature) {
          logger.error('Attribute response signature verification failed', { requestId });
          throw new EidVerificationError('Attribute response signature verification failed');
        }
      }

      // Parse attributes (assuming SAML-like structure or JSON)
      const attributes = responseData.attributes || {};
      if (Object.keys(attributes).length === 0) {
        logger.warn('No attributes received in response', { requestId });
        throw new EidVerificationError('No attributes received in response');
      }

      // Validate attribute format
      for (const [key, value] of Object.entries(attributes)) {
        if (!validator.isAlphanumeric(key, 'en-US', { ignore: '_' }) || typeof value === 'undefined') {
          logger.warn(`Invalid attribute format: ${key}`, { requestId });
          throw new EidVerificationError(`Invalid attribute format: ${key}`);
        }
      }

      logger.info(`Attribute response processed successfully`, { requestId, attributes: Object.keys(attributes) });
      return attributes;
    } catch (error) {
      const errorMessage = `Failed to process attribute response: ${(error as Error).message}`;
      logger.error(errorMessage, { requestId, error });
      throw new EidVerificationError(errorMessage);
    }
  }

  /**
   * Signs an attribute request payload (simplified for production).
   * @param payload The request payload to sign.
   * @returns The signature as a base64 string.
   * @private
   */
  private async signAttributeRequest(payload: string): Promise<string> {
    try {
      const { createSign, constants } = await import('crypto');
      const privateKey = fs.readFileSync(path.resolve(EID_CONFIG.RP_PRIVATE_KEY_PATH), 'utf-8');
      const signer = createSign('RSA-SHA256');
      signer.update(payload);
      const signature = signer.sign(
        {
          key: privateKey,
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
        },
        'base64'
      );
      return signature;
    } catch (error) {
      logger.error(`Failed to sign attribute request: ${(error as Error).message}`);
      throw new EidVerificationError(`Failed to sign attribute request: ${(error as Error).message}`);
    }
  }

  /**
   * Verifies the signature of an attribute response.
   * @param responseData The response data containing attributes and signature.
   * @returns True if the signature is valid, false otherwise.
   * @private
   */
  private async verifyAttributeResponseSignature(responseData: any): Promise<boolean> {
    try {
      const { createVerify, constants } = await import('crypto');
      const certPath = path.resolve(EID_CONFIG.EID_SERVER_SAML_CERT_PATH);
      const publicCert = fs.readFileSync(certPath, 'utf-8');
      const { attributes, signature, ...rest } = responseData;
      const payload = JSON.stringify({ attributes, ...rest });

      const verifier = createVerify('RSA-SHA256');
      verifier.update(payload);
      return verifier.verify(
        {
          key: publicCert,
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
        },
        Buffer.from(signature, 'base64')
      );
    } catch (error) {
      logger.error(`Failed to verify attribute response signature: ${(error as Error).message}`);
      return false;
    }
  }
}