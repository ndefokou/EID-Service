import { Request, Response, NextFunction } from 'express';
import { EID_CONFIG } from '../../config/eid';
import { logger } from '../../utils/logger';
import { EidService } from '../services/eid/EidService';
import { EidSessionError, EidCallbackError, EidVerificationError, EidConfigurationError } from '../utils/eidErrors';
import { IUser } from '../models/User'; // Import IUser
 
 // Initialize EidService
 const eidService = new EidService();
 
 // Get the TC Token URL for a session
 export const getTcTokenURL = async (req: Request, res: Response, next: NextFunction) => {
   try {
     const { sessionId } = req.params;
     const tcTokenURL = await eidService.getTcTokenURL(sessionId);
 
     res.status(200).json({
       success: true,
       sessionId,
       tcTokenURL,
       message: 'TC Token URL retrieved successfully.',
     });
   } catch (error: any) {
     logger.error(`Error getting TC Token URL: ${error.message}`);
     next(error);
   }
 };
 
 // Initiate useID session
 export const initiateUseId = async (req: Request, res: Response, next: NextFunction) => {
   try {
     const userId = req.user ? (req.user as IUser)._id.toString() : null;
     const clientRedirectUrl = req.body.clientRedirectUrl || EID_CONFIG.RP_CALLBACK_URL;
     const requestedAttributes = req.body.requestedAttributes || EID_CONFIG.REQUESTED_ATTRIBUTES;
     const { loaRequested, eidTypeRequested, transactionAttestationRequest, ageVerificationRequested, communityIdRequested, eCardServerAddress } = req.body;

     const { sessionId } = await eidService.initiateUseId(
       userId,
       clientRedirectUrl,
       requestedAttributes,
       loaRequested,
       eidTypeRequested,
       transactionAttestationRequest,
       ageVerificationRequested,
       communityIdRequested,
       eCardServerAddress
     );

     res.status(200).json({
       success: true,
       sessionId,
       message: 'useID session initiated. Ready to build TC Token URL.',
     });
   } catch (error: any) {
     logger.error(`Error initiating useID session: ${error.message}`);
     if (error instanceof EidSessionError || error instanceof EidVerificationError || error instanceof EidConfigurationError || error instanceof EidCallbackError) {
       return next(error);
     }
     next(new EidSessionError(`Failed to initiate useID session: ${error.message}`));
   }
 };

 // Initiate eID authentication process (builds TC Token URL for an existing useID session or a new one)
 export const startEidAuthentication = async (req: Request, res: Response, next: NextFunction) => {
   try {
     const userId = req.user ? (req.user as IUser)._id.toString() : null;
     const clientRedirectUrl = req.body.clientRedirectUrl || EID_CONFIG.RP_CALLBACK_URL;
     const requestedAttributes = req.body.requestedAttributes || EID_CONFIG.REQUESTED_ATTRIBUTES;
     const { loaRequested, eidTypeRequested, transactionAttestationRequest, ageVerificationRequested, communityIdRequested, eCardServerAddress, sessionId } = req.body; // Added sessionId

    const { tcTokenURL, refreshAddress, status } = await eidService.startAuthentication(
      userId,
      clientRedirectUrl,
      requestedAttributes,
      loaRequested,
      eidTypeRequested,
      transactionAttestationRequest,
      ageVerificationRequested,
      communityIdRequested,
      eCardServerAddress,
      sessionId // Pass sessionId to the service
    );

    res.status(200).json({
      success: true,
      sessionId: sessionId,
      tcTokenURL, // Changed from eidClientInteractionUrl to tcTokenURL directly
      refreshAddress,
      status,
      message: 'eID authentication initiated. Redirect to eID client for user interaction.',
    });
  } catch (error: any) {
    logger.error(`Error starting eID authentication: ${error.message}`);
    if (error instanceof EidSessionError || error instanceof EidVerificationError || error instanceof EidConfigurationError || error instanceof EidCallbackError) {
      return next(error);
    }
    next(new EidSessionError(`Failed to initiate eID authentication: ${error.message}`));
  }
};

// Callback endpoint for the eID client
export const eidCallback = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const callbackData = req.body; // Contains sessionId, eidResponse, etc.

    const { sessionId, status, attributes, redirectUrl } = await eidService.processAuthenticationCallback(callbackData);

    // If a redirectUrl is provided, the frontend should use it to navigate
    if (redirectUrl) {
      // Perform HTTP 303 Redirect
      logger.info(`Redirecting to client frontend: ${redirectUrl}`);
      return res.redirect(303, redirectUrl);
    }

    res.status(200).json({
      success: true,
      sessionId,
      status,
      attributes,
      message: 'eID authentication successful, attributes received.',
    });
  } catch (error: any) {
    logger.error(`Error in eID callback: ${error.message}`);
    next(error);
  }
};

// Get current eID authentication status
export const getEidAuthenticationStatus = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { sessionId } = req.params;

    const sessionStatus = await eidService.getAuthenticationStatus(sessionId);

    if (sessionStatus.status === 'NOT_FOUND') {
      throw new EidSessionError('eID session not found or expired.', 404);
    }

    res.status(200).json({
      success: true,
      ...sessionStatus,
      message: 'eID authentication status retrieved successfully.',
    });
  } catch (error: any) {
    logger.error(`Error getting eID authentication status: ${error.message}`);
    next(error);
  }
};

// Get eID attributes for a session
export const getEidAttributes = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { sessionId } = req.params;
    const { attributeNames } = req.body; // Optional: specific attributes to fetch

    const attributes = await eidService.getAttributes(sessionId, attributeNames);

    res.status(200).json({
      success: true,
      sessionId: sessionId,
      attributes: attributes,
      message: 'eID attributes retrieved successfully.',
    });
  } catch (error: any) {
    logger.error(`Error getting eID attributes: ${error.message}`);
    next(error);
  }
};