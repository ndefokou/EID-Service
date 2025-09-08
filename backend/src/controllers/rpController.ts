import { Request, Response, NextFunction } from 'express';
import { logger } from '../../utils/logger';
import { EID_CONFIG } from '../../config/eid';
import { EidService } from '../services/eid/EidService';
import { AuthService } from '../services/auth/AuthService'; // Import AuthService
import { EidCallbackError, EidSessionError, EidVerificationError } from '@root/src/utils/eidErrors';

const eidService = new EidService();
const authService = new AuthService(); // Instantiate AuthService

/**
 * Handles the Relying Party (RP) callback after eID authentication.
 * This endpoint receives the result from the eID server after a user
 * has successfully authenticated with their eID card.
 * @param req The Express request object.
 * @param res The Express response object.
 * @param next The Express next middleware function.
 */
export const rpCallback = async (req: Request, res: Response, next: NextFunction) => {
  logger.info(`RP Callback received. Request body: ${JSON.stringify(req.body)}`);

  try {
    // 1. Validate callback data
    if (!req.body || typeof req.body.SAMLResponse !== 'string') {
      logger.warn('Invalid RP Callback: Missing or malformed SAMLResponse.');
      throw new EidCallbackError('Invalid callback data: SAMLResponse missing or not a string.');
    }

    // 2. Process the authentication callback using the EidService
    const authenticationResult = await eidService.processAuthenticationCallback({
      SAMLResponse: req.body.SAMLResponse,
      sessionId: req.body.sessionId, // Assuming sessionId is also passed in the body
    });

    // 3. Handle successful authentication
    if (authenticationResult.status === 'SUCCESS') {
      logger.info(`eID authentication successful for session ${authenticationResult.sessionId}. Redirecting to frontend.`);
      try {
        // Generate a short-lived, one-time token for frontend redirection.
        // This token allows the frontend to securely fetch user details via a subsequent API call.
        // It avoids putting sensitive user data directly into the URL.
        const oneTimeToken = authService.generateOneTimeFrontendToken(authenticationResult.userId);

        const redirectUrl = authenticationResult.redirectUrl || EID_CONFIG.FRONTEND_SUCCESS_REDIRECT_URL;
        const queryParams = new URLSearchParams({
          status: 'success',
          sessionId: authenticationResult.sessionId,
          token: oneTimeToken, // Include the one-time token in the redirect URL
        }).toString();

        // For security, it's often better to issue a server-side token and redirect with it,
        // letting the frontend fetch details securely.
        res.redirect(`${redirectUrl}?${queryParams}`);
      } catch (tokenError: unknown) {
        logger.error(`Failed to generate frontend token for session ${authenticationResult.sessionId}: ${tokenError}`);
        // If token generation fails, redirect to an error page
        const redirectUrl = authenticationResult.redirectUrl || EID_CONFIG.FRONTEND_ERROR_REDIRECT_URL;
        const queryParams = new URLSearchParams({
          status: 'failed',
          sessionId: authenticationResult.sessionId,
          message: 'Failed to complete authentication: Token generation error.',
        }).toString();
        res.redirect(`${redirectUrl}?${queryParams}`);
      }
    } else {
      // Handle non-success status from eID service (e.g., FAILED, LOGOUT)
      logger.warn(`eID authentication not successful for session ${authenticationResult.sessionId}. Status: ${authenticationResult.status}`);
      const redirectUrl = authenticationResult.redirectUrl || EID_CONFIG.FRONTEND_ERROR_REDIRECT_URL;
      const queryParams = new URLSearchParams({
        status: 'failed',
        sessionId: authenticationResult.sessionId,
        message: authenticationResult.message || `eID authentication ${authenticationResult.status}.`,
      }).toString();
      res.redirect(`${redirectUrl}?${queryParams}`);
    }
  } catch (error: unknown) { // Explicitly type error as unknown
    // 4. Error handling and edge cases
    if (error instanceof EidCallbackError) {
      logger.error(`RP Callback Validation Error: ${error.message}`);
      res.status(400).json({ message: error.message, code: error.name });
    } else if (error instanceof EidSessionError) {
      logger.error(`RP Callback Session Error: ${error.message}`);
      res.status(404).json({ message: error.message, code: error.name });
    } else if (error instanceof EidVerificationError) {
      logger.error(`RP Callback Verification Error: ${error.message}`);
      res.status(403).json({ message: error.message, code: error.name });
    } else if (error instanceof Error) {
      logger.error(`Unhandled error in RP Callback: ${error.message}`, error.stack);
      res.status(500).json({ message: 'Internal server error during eID callback processing.', code: 'INTERNAL_SERVER_ERROR' });
    } else {
      // Generic error handling for unknown types
      const errorMessage = (error && typeof error === 'object' && 'message' in error)
        ? (error as { message: string }).message
        : 'An unexpected error occurred.';
      const errorCode = (error && typeof error === 'object' && 'name' in error)
        ? (error as { name: string }).name
        : 'UNKNOWN_ERROR';
      logger.error(`Unknown error in RP Callback: ${errorMessage}`);
      res.status(500).json({ message: errorMessage, code: errorCode });
    }
    next(error); // Pass error to error handling middleware for centralized logging/monitoring
  }
};

/**
 * Initiates an attribute request to the eID server.
 * This might be used if certain attributes are not part of the initial authentication flow
 * or need to be fetched separately.
 * @param req The Express request object.
 * @param res The Express response object.
 * @param next The Express next middleware function.
 */
export const requestAttributes = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { sessionId, requestedAttributes } = req.body;
    logger.info(`Request for attributes received for session ${sessionId} with attributes: ${JSON.stringify(requestedAttributes)}`);

    const attributes = await eidService.getAttributes(sessionId, requestedAttributes);

    logger.info(`Successfully fetched attributes for session ${sessionId}.`);
    res.status(200).json({
      message: 'Attributes successfully fetched.',
      sessionId,
      attributes,
    });
  } catch (error: unknown) { // Explicitly type error as unknown
    if (error instanceof EidSessionError) {
      logger.error(`Attribute Request Session Error: ${error.message}`);
      res.status(404).json({ message: error.message, code: error.name });
    } else if (error instanceof EidVerificationError) {
      logger.error(`Attribute Request Verification Error: ${error.message}`);
      res.status(403).json({ message: error.message, code: error.name });
    } else if (error instanceof Error) {
      logger.error(`Unhandled error requesting attributes: ${error.message}`, error.stack);
      res.status(500).json({ message: 'Internal server error during attribute request.', code: 'INTERNAL_SERVER_ERROR' });
    } else {
      const errorMessage = (error && typeof error === 'object' && 'message' in error)
        ? (error as { message: string }).message
        : 'An unexpected error occurred.';
      const errorCode = (error && typeof error === 'object' && 'name' in error)
        ? (error as { name: string }).name
        : 'UNKNOWN_ERROR';
      logger.error(`Unknown error requesting attributes: ${errorMessage}`);
      res.status(500).json({ message: errorMessage, code: errorCode });
    }
    next(error); // Pass error to error handling middleware
  }
};

/**
 * Provides the Relying Party (RP) configuration to the frontend or external clients.
 * This can include the RP ID, callback URLs, and other public configuration details.
 * @param req The Express request object.
 * @param res The Express response object.
 */
export const getRpConfig = (req: Request, res: Response) => {
  try {
    res.status(200).json({
      rpId: EID_CONFIG.RP_ID,
      rpCallbackUrl: EID_CONFIG.RP_CALLBACK_URL,
      // Add any other public RP configuration details here
    });
  } catch (error) {
    if (error instanceof Error) {
      logger.error(`Error fetching RP config: ${error.message}`);
    } else {
      logger.error(`Unknown error fetching RP config: ${error}`);
    }
    res.status(500).json({ message: 'Error fetching RP configuration.' });
  }
};