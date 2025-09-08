import { Router } from 'express';
import * as eidController from '../controllers/eidController';

const router = Router();

// Endpoint to initiate a useID session
router.post('/initiate-useid', eidController.initiateUseId);

// Endpoint to initiate eID authentication (builds TC Token URL)
router.post('/start', eidController.startEidAuthentication);

// Endpoint for eID client callback (after successful authentication on client side)
router.post('/callback', eidController.eidCallback);

// Endpoint to poll for eID authentication status (for frontend to check progress)
router.get('/status/:sessionId', eidController.getEidAuthenticationStatus);

// Endpoint to retrieve attributes after successful eID authentication
router.get('/attributes/:sessionId', eidController.getEidAttributes);

// New endpoint to get the TC Token URL for the eID client
router.get('/tc-token-url/:sessionId', eidController.getTcTokenURL);

export default router;