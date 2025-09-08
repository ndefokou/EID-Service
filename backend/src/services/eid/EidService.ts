import { logger } from '@root/utils/logger';
import { Tr03124Protocol } from './Tr03124Protocol';
import { SessionManager } from './SessionManager';
import { CertificateValidator } from './CertificateValidator';
import { SignatureVerifier } from './SignatureVerifier';
import axios, { AxiosError } from 'axios';
import * as https from 'https';
import { EID_CONFIG } from '@root/config/eid';
import { EidSession, IEidSession } from '@root/src/models/EidSession';
import { EidVerificationError, EidSessionError, EidCallbackError, EidConfigurationError } from '@root/src/utils/eidErrors';
import validator from 'validator';

/**
 * Service class for orchestrating eID authentication and attribute release flow.
 * Integrates TR-03124 protocol, session management, certificate validation, and signature verification.
 * Designed for production with robust error handling, logging, and security measures.
 */
export class EidService {
  private tr03124Protocol: Tr03124Protocol;
  private sessionManager: SessionManager;
  private certificateValidator: CertificateValidator;
  private signatureVerifier: SignatureVerifier;

  constructor() {
    this.tr03124Protocol = new Tr03124Protocol();
    this.sessionManager = new SessionManager();
    this.certificateValidator = new CertificateValidator();
    this.signatureVerifier = new SignatureVerifier();
    logger.info('EidService initialized with production configuration.');
  }


  /**
   * Initiates a useID session, creating a new eID session without generating a tcTokenURL yet.
   * This is the first step in a multi-step eID authentication flow.
   * @param userId The ID of the user initiating authentication (nullable if not logged in).
   * @param clientRedirectUrl The URL to redirect the frontend after eID client interaction.
   * @param requestedAttributes List of attributes to request from the eID card.
   * @param loaRequested Requested Level of Assurance (LoA).
   * @param eidTypeRequested Requested eID types.
   * @param transactionAttestationRequest Optional transaction attestation data.
   * @param ageVerificationRequested Flag for age verification request.
   * @param communityIdRequested Optional community ID for verification.
   * @param eCardServerAddress Optional eID server address override.
   * @returns The created session ID.
   * @throws EidSessionError if session creation fails.
   */
  public async initiateUseId(
    userId: string | null,
    clientRedirectUrl: string,
    requestedAttributes: string[] = [],
    loaRequested?: string,
    eidTypeRequested?: string[],
    transactionAttestationRequest?: object,
    ageVerificationRequested?: boolean,
    communityIdRequested?: string,
    eCardServerAddress?: string
  ): Promise<{ sessionId: string }> {
    logger.info(`Initiating useID for user: ${userId || 'anonymous'}, redirectUrl: ${clientRedirectUrl}`);

    // Validate inputs
    if (requestedAttributes.some(attr => !validator.isAlphanumeric(attr))) {
      logger.error('Invalid requested attributes provided for useID initiation.');
      throw new EidVerificationError('Requested attributes must be alphanumeric.');
    }

    try {
      const eidSession = await this.sessionManager.createSession(
        userId,
        clientRedirectUrl,
        requestedAttributes,
        loaRequested,
        eidTypeRequested,
        transactionAttestationRequest,
        ageVerificationRequested,
        communityIdRequested,
        eCardServerAddress || EID_CONFIG.EID_SERVER_BASE_URL,
        'USEID_INITIATED' // Set initial status to indicate useID initiation
      );
      logger.info(`useID session initiated with ID: ${eidSession.sessionId}`);

      // Create an HTTPS agent to accept self-signed certificates for development/testing
      const httpsAgent = new https.Agent({
        rejectUnauthorized: false, // WARNING: Do not use in production without proper certificate validation
      });
      logger.warn('WARNING: Accepting self-signed certificates for eID server connection. This should only be used in development/testing environments.');

      // Construct SOAP XML payload for useID request
      const soapPayload = `
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/">
   <soapenv:Header/>
   <soapenv:Body>
      <eid:useIDRequest>
         <eid:UseOperations>
            <eid:DocumentType>REQUIRED</eid:DocumentType>
            <eid:IssuingState>REQUIRED</eid:IssuingState>
            <eid:DateOfExpiry>REQUIRED</eid:DateOfExpiry>
            <eid:GivenNames>REQUIRED</eid:GivenNames>
            <eid:FamilyNames>REQUIRED</eid:FamilyNames>
            <!-- Hardcoding a few fields from the example to debug the XML deserialization error -->
            <!-- Uncomment and expand as needed once the basic structure is accepted by the server -->
            <!-- <eid:ArtisticName>ALLOWED</eid:ArtisticName> -->
            <!-- <eid:AcademicTitle>ALLOWED</eid:AcademicTitle> -->
            <eid:DateOfBirth>REQUIRED</eid:DateOfBirth>
            <!-- <eid:PlaceOfBirth>REQUIRED</eid:PlaceOfBirth> -->
            <!-- <eid:Nationality>REQUIRED</eid:Nationality> -->
            <!-- <eid:BirthName>REQUIRED</eid:BirthName> -->
            <!-- <eid:PlaceOfResidence>REQUIRED</eid:PlaceOfResidence> -->
            <!-- <eid:CommunityID/> -->
            <!-- <eid:ResidencePermitI/> -->
            <!-- <eid:RestrictedID>REQUIRED</eid:RestrictedID> -->
            <!-- <eid:AgeVerification>REQUIRED</eid:AgeVerification> -->
            <!-- <eid:PlaceVerification>REQUIRED</eid:PlaceVerification> -->
         </eid:UseOperations>
         ${eidSession.ageVerificationRequested ? '<eid:AgeVerificationRequest><eid:Age>18</eid:Age></eid:AgeVerificationRequest>' : ''}
         ${eidSession.communityIdRequested ? `<eid:PlaceVerificationRequest><eid:CommunityID>${eidSession.communityIdRequested}</eid:CommunityID></eid:PlaceVerificationRequest>` : ''}
         <!-- The following elements are examples from the BSI documentation and can be conditionally included: -->
         <!--
         <eid:TransactionAttestationRequest>
            <eid:TransactionAttestationFormat>
               http://bsi.bund.de/eID/ExampleAttestationFormat
            </eid:TransactionAttestationFormat>
            <eid:TransactionContext>id599456-df</eid:TransactionContext>
         </eid:TransactionAttestationRequest>
         <eid:LevelOfAssuranceRequest>
            http://bsi.bund.de/eID/LoA/hoch
         </eid:LevelOfAssuranceRequest>
         <eid:EIDTypeRequest>
            <eid:SECertified>ALLOWED</eid:SECertified>
            <eid:SEEndorsed>ALLOWED</eid:SEEndorsed>
         </eid:EIDTypeRequest>
         -->
      </eid:useIDRequest>
   </soapenv:Body>
</soapenv:Envelope>`;

      // Send use ID request to the eID server with SOAP XML payload
      logger.info(`Sending use ID SOAP request to eID server: ${EID_CONFIG.EID_SERVER_BASE_URL}`);
      try {
        await axios.post(EID_CONFIG.EID_SERVER_BASE_URL, soapPayload, {
          headers: {
            'Content-Type': 'text/xml',
          },
          timeout: EID_CONFIG.EID_SERVER_TIMEOUT,
          httpsAgent,
        });
        logger.info(`use ID SOAP request successfully sent for session: ${eidSession.sessionId}`);
      } catch (axiosError: any) {
        logger.error(`Failed to send use ID SOAP request to eID server for session ${eidSession.sessionId}: ${axiosError.message}`);
        throw new EidSessionError(`Failed to send use ID request: ${axiosError.message}`);
      }

      return { sessionId: eidSession.sessionId };
    } catch (error: any) {
      logger.error(`Failed to initiate useID session: ${error.message}`);
      throw error instanceof EidSessionError || error instanceof EidVerificationError || error instanceof EidConfigurationError || error instanceof EidCallbackError
        ? error
        : new EidSessionError(`useID initiation failed: ${error.message}`);
    }
  }

  /**
   * Generates the TC Token URL for an existing eID session or a new one.
   * This is the second step in a multi-step eID authentication flow after useID initiation.
   * @param sessionId Optional: The ID of an existing eID session. If not provided, a new session is created.
   * @param userId The ID of the user initiating authentication (nullable if not logged in).
   * @param clientRedirectUrl The URL to redirect the frontend after eID client interaction.
   * @param requestedAttributes List of attributes to request from the eID card.
   * @param loaRequested Requested Level of Assurance (LoA).
   * @param eidTypeRequested Requested eID types.
   * @param transactionAttestationRequest Optional transaction attestation data.
   * @param ageVerificationRequested Flag for age verification request.
   * @param communityIdRequested Optional community ID for verification.
   * @param eCardServerAddress Optional eID server address override.
   * @returns Authentication data including session ID and tcTokenURL.
   * @throws EidSessionError if session creation or update fails.
   * @throws EidVerificationError if auth request generation fails.
   */
  public async startAuthentication(
    userId: string | null,
    clientRedirectUrl: string,
    requestedAttributes: string[] = [],
    loaRequested?: string,
    eidTypeRequested?: string[],
    transactionAttestationRequest?: object,
    ageVerificationRequested?: boolean,
    communityIdRequested?: string,
    eCardServerAddress?: string,
    sessionId?: string // Make sessionId optional
  ): Promise<any> {
    logger.info(`Starting eID authentication for user: ${userId || 'anonymous'}, redirectUrl: ${clientRedirectUrl}, existingSessionId: ${sessionId}`);

    // Validate inputs
    if (requestedAttributes.some(attr => !validator.isAlphanumeric(attr))) {
      logger.error('Invalid requested attributes provided.');
      throw new EidVerificationError('Requested attributes must be alphanumeric.');
    }

    let currentSession: IEidSession; // Corrected type annotation

    try {
      if (sessionId) {
        // Use existing session
        const existingSession = await this.sessionManager.getSession(sessionId);
        if (!existingSession) {
          logger.error(`Existing eID Session not found for ID: ${sessionId}`);
          throw new EidSessionError('eID Session not found or expired for provided ID.');
        }
        // Ensure the existing session is in a state where TC Token URL can be generated
        if (existingSession.status !== 'USEID_INITIATED' && existingSession.status !== 'INITIATED') {
          logger.error(`Session ${sessionId} is in status ${existingSession.status}, cannot generate tcTokenURL.`);
          throw new EidSessionError('Invalid session status for generating TC Token URL.');
        }
        currentSession = existingSession;
      } else {
        // Create a new eID session if no sessionId is provided
        currentSession = await this.sessionManager.createSession(
          userId,
          clientRedirectUrl,
          requestedAttributes,
          loaRequested,
          eidTypeRequested,
          transactionAttestationRequest,
          ageVerificationRequested,
          communityIdRequested,
          eCardServerAddress || EID_CONFIG.EID_SERVER_BASE_URL,
          'INITIATED' // Default status for a new session
        );
      }

      // Generate TR-03124 authentication request
      const { tcTokenURL } = await this.tr03124Protocol.generateAuthRequest(
        currentSession.sessionId,
        EID_CONFIG.RP_CALLBACK_URL
      );

      await this.sessionManager.updateSession(currentSession.sessionId, {
        $set: {
          tcTokenURL,
          status: 'PENDING' // Update status once tcTokenURL is generated
        }
      });

      // Construct eID client interaction URL (this will be the tcTokenURL)
      const eidClientInteractionUrl = tcTokenURL;

      logger.debug(`Generated eID client interaction URL: ${eidClientInteractionUrl}`);

      return {
        sessionId: currentSession.sessionId,
        tcTokenURL, // Exposing tcTokenURL directly as the interaction URL
        status: 'AUTHENTICATION_INITIATED',
      };
    } catch (error: any) {
      logger.error(`Failed to start authentication: ${error.message}`);
      throw error instanceof EidSessionError || error instanceof EidVerificationError || error instanceof EidConfigurationError || error instanceof EidCallbackError
        ? error
        : new EidSessionError(`Authentication initiation failed: ${error.message}`);
    }
  }

  /**
   * Retrieves the tcTokenURL for a given session.
   * @param sessionId The ID of the eID session.
   * @returns The tcTokenURL if available.
   * @throws EidSessionError if session is not found or tcTokenURL is missing.
   */
  public async getTcTokenURL(sessionId: string): Promise<string> {
    logger.debug(`Retrieving tcTokenURL for session: ${sessionId}`);

     if (!validator.isUUID(sessionId)) {
       logger.error('Invalid sessionId provided.');
       throw new EidSessionError('Invalid session ID.');
     }

     const eidSession = await this.sessionManager.getSession(sessionId);
     if (!eidSession) {
       logger.error(`eID Session not found for tcTokenURL retrieval: ${sessionId}`);
       throw new EidSessionError('eID Session not found or expired.');
     }

     if (!eidSession.tcTokenURL) {
       logger.error(`tcTokenURL not found for session: ${sessionId}`);
       throw new EidSessionError('TC Token URL not available for this session.');
     }

     return eidSession.tcTokenURL;
   }

  /**
   * Processes the callback from the eID server, validating the response and updating the session.
   * @param callbackData Data received from the eID server's callback.
   * @returns Authentication result including user attributes and redirect URL.
   * @throws EidCallbackError if callback data is invalid.
   * @throws EidSessionError if session is not found.
   * @throws EidVerificationError if any validation fails.
   */
  public async processAuthenticationCallback(callbackData: any): Promise<any> {
    logger.info('Processing eID authentication callback.');

    // Validate callback data
    if (!callbackData?.sessionId || !callbackData?.eidResponse) {
      logger.error('Missing sessionId or eidResponse in callback data.');
      throw new EidCallbackError('Invalid callback data: Missing sessionId or eidResponse.');
    }

    const { sessionId, eidResponse } = callbackData;

    try {
      // Retrieve session
      const eidSession = await this.sessionManager.getSession(sessionId);
      if (!eidSession) {
        logger.error(`eID Session not found for ID: ${sessionId}`);
        throw new EidSessionError('eID Session not found or expired.');
      }

      // Process TR-03124 response
      const processedAuthResult = await this.tr03124Protocol.processAuthResponse(eidResponse, sessionId);
      if (processedAuthResult.status !== 'SUCCESS') {
        logger.warn(`TR-03124 authentication failed for session ${sessionId}. Status: ${processedAuthResult.status}`);
        await this.sessionManager.updateSessionStatus(sessionId, 'FAILED', processedAuthResult.status);
        throw new EidVerificationError(`eID authentication failed: ${processedAuthResult.status}`);
      }

      // Validate certificate chain
      const certificateChain = processedAuthResult.certificateChain;
      if (!certificateChain || certificateChain.length === 0) {
        logger.error(`Certificate chain missing for session ${sessionId}`);
        await this.sessionManager.updateSessionStatus(sessionId, 'FAILED', 'CERTIFICATE_MISSING');
        throw new EidVerificationError('eID server certificate chain missing.');
      }
      for (const cert of certificateChain) {
        if (!await this.certificateValidator.validateCertificate(cert)) {
          logger.error(`Certificate validation failed for session ${sessionId}`);
          await this.sessionManager.updateSessionStatus(sessionId, 'FAILED', 'CERTIFICATE_VALIDATION_FAILED');
          throw new EidVerificationError('eID server certificate validation failed.');
        }
      }
      logger.debug(`Certificate chain validated for session ${sessionId}.`);

      // Perform passive authentication
      const isDocumentValid = await this.performPassiveAuthentication(processedAuthResult.documentData);
      if (!isDocumentValid) {
        logger.error(`Passive authentication failed for session ${sessionId}`);
        await this.sessionManager.updateSessionStatus(sessionId, 'FAILED', 'DOCUMENT_INVALID');
        throw new EidVerificationError('eID document validity check failed.');
      }

      // Check blacklist
      const cardIdentifier = processedAuthResult.cardIdentifier;
      if (!cardIdentifier) {
        logger.error(`Card identifier is missing for session ${sessionId}`);
        await this.sessionManager.updateSessionStatus(sessionId, 'FAILED', 'CARD_IDENTIFIER_MISSING');
        throw new EidVerificationError('eID card identifier is missing.');
      }
      const isCardBlacklisted = await this.checkEidBlacklist(cardIdentifier);
      if (isCardBlacklisted) {
        logger.error(`eID card is blacklisted for session ${sessionId}`);
        await this.sessionManager.updateSessionStatus(sessionId, 'FAILED', 'CARD_BLACKLISTED');
        throw new EidVerificationError('eID card is blacklisted.');
      }

      // Perform chip authentication
      const isChipAuthenticated = await this.performChipAuthentication(sessionId, processedAuthResult.chipData);
      if (!isChipAuthenticated) {
        logger.error(`Chip authentication failed for session ${sessionId}`);
        await this.sessionManager.updateSessionStatus(sessionId, 'FAILED', 'CHIP_AUTHENTICATION_FAILED');
        throw new EidVerificationError('eID chip authentication failed.');
      }

      // Verify signature
      const { signature, signedData } = processedAuthResult;
      if (!signature || !signedData || !await this.signatureVerifier.verifySignature(signedData, signature, certificateChain[0])) {
        logger.error(`Signature verification failed for session ${sessionId}`);
        await this.sessionManager.updateSessionStatus(sessionId, 'FAILED', 'SIGNATURE_VERIFICATION_FAILED');
        throw new EidVerificationError('eID response signature verification failed.');
      }

      // Validate nonce
      const receivedNonce = processedAuthResult.nonce;
      if (!receivedNonce || receivedNonce !== eidSession.nonce) {
        logger.error(`Nonce mismatch for session ${sessionId}. Expected: ${eidSession.nonce}, Received: ${receivedNonce}`);
        await this.sessionManager.updateSessionStatus(sessionId, 'FAILED', 'NONCE_MISMATCH');
        throw new EidVerificationError('Nonce mismatch during eID authentication.');
      }

      // Validate requested attributes
      const requestedAttributes = eidSession.requestedAttributes;
      const receivedAttributes = processedAuthResult.attributes ?? {};
      const missingAttributes = requestedAttributes.filter((attr: string) => !receivedAttributes[attr]);
      if (missingAttributes.length > 0) {
        logger.warn(`Missing attributes for session ${sessionId}: ${missingAttributes.join(', ')}`);
        await this.sessionManager.updateSessionStatus(sessionId, 'FAILED', 'MISSING_ATTRIBUTES');
        throw new EidVerificationError(`Missing mandatory attributes: ${missingAttributes.join(', ')}`);
      }

      // Update session
      const updatePayload = {
        $set: {
          status: 'COMPLETED',
          attributes: receivedAttributes,
          loaResult: processedAuthResult.loaResult,
          eidTypeResult: processedAuthResult.eidTypeResult,
          ageVerificationResult: processedAuthResult.ageVerificationResult,
          communityIdResult: processedAuthResult.communityIdResult,
        },
        $inc: { requestCounter: 1 },
      };
      await this.sessionManager.updateSession(sessionId, updatePayload);

      logger.info(`eID authentication successful for session ${sessionId}.`);
      return {
        sessionId,
        status: 'SUCCESS',
        attributes: receivedAttributes,
        loaResult: processedAuthResult.loaResult,
        eidTypeResult: processedAuthResult.eidTypeResult,
        ageVerificationResult: processedAuthResult.ageVerificationResult,
        communityIdResult: processedAuthResult.communityIdResult,
        redirectUrl: eidSession.clientRedirectUrl,
      };
    } catch (error: any) {
      logger.error(`Callback processing failed for session ${sessionId}: ${error.message}`);
      throw error instanceof EidVerificationError || error instanceof EidSessionError || error instanceof EidCallbackError
        ? error
        : new EidVerificationError(`Callback processing failed: ${error.message}`);
    }
  }

  /**
   * Fetches additional attributes for an existing eID session.
   * @param sessionId The ID of the eID session.
   * @param attributeNames Array of attribute names to request.
   * @returns Fetched attributes.
   * @throws EidSessionError if session is not found.
   * @throws EidVerificationError if attribute fetching fails.
   */
  public async getAttributes(sessionId: string, attributeNames: string[]): Promise<any> {
    logger.info(`Fetching attributes for session ${sessionId}: ${attributeNames.join(', ')}`);

    // Validate inputs
    if (!validator.isUUID(sessionId)) {
      logger.error('Invalid sessionId provided.');
      throw new EidSessionError('Invalid session ID.');
    }
    if (attributeNames.some(attr => !validator.isAlphanumeric(attr))) {
      logger.error('Invalid attribute names provided.');
      throw new EidVerificationError('Attribute names must be alphanumeric.');
    }

    try {
      const eidSession = await this.sessionManager.getSession(sessionId);
      if (!eidSession) {
        logger.error(`eID Session not found for ID: ${sessionId}`);
        throw new EidSessionError('eID Session not found or expired.');
      }

      const attributeRequest = await this.tr03124Protocol.generateAttributeRequest(sessionId, attributeNames);
      
      // Make HTTP request to eID server with retry mechanism
      let eidServerResponse;
      for (let attempt = 1; attempt <= EID_CONFIG.MAX_RETRIES; attempt++) {
        try {
          eidServerResponse = await axios.post(
            `${EID_CONFIG.EID_SERVER_BASE_URL}/attribute-request`,
            attributeRequest,
            { timeout: EID_CONFIG.EID_SERVER_TIMEOUT }
          );
          break;
        } catch (error: any) {
          logger.warn(`Attempt ${attempt} failed for attribute request: ${error.message}`);
          if (attempt === EID_CONFIG.MAX_RETRIES) {
            throw new EidVerificationError(`Failed to fetch attributes after ${EID_CONFIG.MAX_RETRIES} attempts: ${error.message}`);
          }
          await new Promise(resolve => setTimeout(resolve, EID_CONFIG.RETRY_DELAY));
        }
      }

      if (!eidServerResponse) {
        throw new EidVerificationError('eID server did not return a response for attribute request.');
      }
      const processedAttributes = await this.tr03124Protocol.processAttributeResponse(eidServerResponse.data);
      await this.sessionManager.updateSessionAttributes(sessionId, processedAttributes);

      logger.info(`Successfully fetched attributes for session ${sessionId}.`);
      return processedAttributes;
    } catch (error: any) {
      logger.error(`Error fetching attributes for session ${sessionId}: ${error.message}`);
      throw error instanceof EidVerificationError || error instanceof EidSessionError || error instanceof EidConfigurationError || error instanceof EidCallbackError
        ? error
        : new EidVerificationError(`Failed to fetch attributes: ${error.message}`);
    }
  }

  /**
   * Retrieves the current status of an eID authentication session.
   * @param sessionId The ID of the eID session.
   * @returns Session status and associated data.
   * @throws EidSessionError if session is not found.
   */
  public async getAuthenticationStatus(sessionId: string): Promise<any> {
    logger.debug(`Retrieving authentication status for session: ${sessionId}`);

    if (!validator.isUUID(sessionId)) {
      logger.error('Invalid sessionId provided.');
      throw new EidSessionError('Invalid session ID.');
    }

    try {
      const eidSession = await this.sessionManager.getSession(sessionId);
      if (!eidSession) {
        logger.warn(`eID Session not found for status check: ${sessionId}`);
        return { status: 'NOT_FOUND', message: 'eID Session not found or expired.' };
      }

      return {
        sessionId: eidSession.sessionId,
        status: eidSession.status,
        attributes: eidSession.attributes,
        userId: eidSession.userId,
        createdAt: eidSession.createdAt,
        updatedAt: eidSession.updatedAt,
        loaRequested: eidSession.loaRequested,
        loaResult: eidSession.loaResult,
        eidTypeRequested: eidSession.eidTypeRequested,
        eidTypeResult: eidSession.eidTypeResult,
        ageVerificationRequested: eidSession.ageVerificationRequested,
        ageVerificationResult: eidSession.ageVerificationResult,
        communityIdRequested: eidSession.communityIdRequested,
        communityIdResult: eidSession.communityIdResult,
        requestCounter: eidSession.requestCounter,
        transactionAttestationRequest: eidSession.transactionAttestationRequest,
        transactionAttestationResponse: eidSession.transactionAttestationResponse,
        operationsAllowedByUser: eidSession.operationsAllowedByUser,
        eCardServerAddress: eidSession.eCardServerAddress,
      };
    } catch (error: any) {
      logger.error(`Failed to retrieve status for session ${sessionId}: ${error.message}`);
      throw new EidSessionError(`Status retrieval failed: ${error.message}`);
    }
  }

  /**
   * Performs passive authentication to validate eID document security objects.
   * @param documentData The eID document data.
   * @returns True if the document is valid, false otherwise.
   * @throws EidVerificationError if validation fails critically.
   */
  private async performPassiveAuthentication(documentData: any): Promise<boolean> {
    logger.debug('Performing passive authentication for document data validation.');

    try {
      if (!documentData || !documentData.documentNumber || !documentData.validityDate || !documentData.securityObject) {
        logger.warn('Invalid document data for passive authentication.');
        return false;
      }

      // Assume securityObject contains a signed hash of document data
      const { securityObject, documentNumber, validityDate } = documentData;
      const isValid = await this.signatureVerifier.verifySignature(
        `${documentNumber}:${validityDate}`,
        securityObject.signature,
        securityObject.certificate
      );

      if (!isValid) {
        logger.warn('Passive authentication failed: Invalid signature.');
        return false;
      }

      // Check document validity date
      const currentDate = new Date();
      const validity = new Date(validityDate);
      if (validity < currentDate) {
        logger.warn('Passive authentication failed: Document expired.');
        return false;
      }

      logger.debug('Passive authentication successful.');
      return true;
    } catch (error: any) {
      logger.error(`Passive authentication error: ${error.message}`);
      throw new EidVerificationError(`Passive authentication failed: ${error.message}`);
    }
  }

  /**
   * Performs chip authentication using cryptographic challenge-response.
   * @param sessionId The current session ID.
   * @param chipData Data from the eID chip.
   * @returns True if chip authentication succeeds, false otherwise.
   * @throws EidVerificationError if authentication fails critically.
   */
  private async performChipAuthentication(sessionId: string, chipData: any): Promise<boolean> {
    logger.debug(`Performing chip authentication for session ${sessionId}.`);

    try {
      if (!chipData || !chipData.challenge || !chipData.response || !chipData.publicKey) {
        logger.warn(`Invalid chip data for session ${sessionId}.`);
        return false;
      }

      // Simulate challenge-response using public key cryptography
      const challenge = chipData.challenge;
      const response = chipData.response;
      const isValid = await this.signatureVerifier.verifySignature(challenge, response, chipData.publicKey);

      if (!isValid) {
        logger.warn(`Chip authentication failed for session ${sessionId}: Invalid response.`);
        return false;
      }

      logger.debug(`Chip authentication successful for session ${sessionId}.`);
      return true;
    } catch (error: any) {
      logger.error(`Chip authentication error for session ${sessionId}: ${error.message}`);
      throw new EidVerificationError(`Chip authentication failed: ${error.message}`);
    }
  }

  /**
   * Checks if an eID card or certificate is blacklisted.
   * @param cardIdentifier The eID card identifier.
   * @returns True if blacklisted, false otherwise.
   * @throws EidVerificationError if blacklist check fails.
   */
  private async checkEidBlacklist(cardIdentifier: string): Promise<boolean> {
    logger.debug(`Checking eID blacklist for card: ${cardIdentifier}.`);

    try {
      // Query external blacklist service or database
      const response = await axios.get(
        `${EID_CONFIG.BLACKLIST_SERVICE_URL}/check?identifier=${encodeURIComponent(cardIdentifier)}`,
        { timeout: EID_CONFIG.EID_SERVER_TIMEOUT }
      );

      const isBlacklisted = response.data?.isBlacklisted || false;
      if (isBlacklisted) {
        logger.warn(`eID card ${cardIdentifier} is blacklisted.`);
        return true;
      }

      logger.debug(`eID card ${cardIdentifier} is not blacklisted.`);
      return false;
    } catch (error: any) {
      logger.error(`Blacklist check failed for card ${cardIdentifier}: ${error.message}`);
      throw new EidVerificationError(`Blacklist check failed: ${error.message}`);
    }
  }

  /**
   * Retrieves eID service information.
   * @returns Service metadata including version, supported eID types, and status.
   */
  public async getServerInfo(): Promise<any> {
    logger.info('Retrieving eID service information.');

    try {
      return {
        serviceName: 'German eID Service Backend',
        version: process.env.npm_package_version || '1.0.0',
        supportedEidTypes: EID_CONFIG.SUPPORTED_EID_TYPES,
        supportedLoa: EID_CONFIG.SUPPORTED_LOA,
        rpId: EID_CONFIG.RP_ID,
        rpCallbackUrl: EID_CONFIG.RP_CALLBACK_URL,
        status: 'Operational',
        message: 'eID Service is running and ready for authentication requests.',
      };
    } catch (error: any) {
      logger.error(`Failed to retrieve server info: ${error.message}`);
      throw new EidVerificationError(`Server info retrieval failed: ${error.message}`);
    }
  }
}