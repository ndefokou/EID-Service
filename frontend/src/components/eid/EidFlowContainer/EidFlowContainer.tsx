import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { UserIdentification } from '../UserIdentification/UserIdentification';
import { AttributeConsent } from '../AttributeConsent/AttributeConsent';
import { LoadingSpinner } from '../../common/LoadingSpinner/LoadingSpinner';
import { Button } from '../../common/Button/Button'; 
import styles from './EidFlowContainer.module.scss';
import { EID_CONFIG } from '../../../config/eid'; 
import API_BASE_URL from '../../../config/api';
// --- Constants ---
const EID_START_ENDPOINT = `${API_BASE_URL}/eid/start`;
const EID_CALLBACK_URL = window.location.origin + '/eid-callback';

// --- Error Messages ---
const SESSION_ID_MISSING_ERROR = 'Session ID is missing. Cannot start eID authentication.';
const EID_START_FAILURE_MESSAGE = 'Failed to initiate eID authentication.';
const NETWORK_ERROR_MESSAGE = 'Network error during eID initiation.';

// --- Helper Functions ---
const handleEidError = (
  err: unknown,
  defaultMessage: string,
  setError: (msg: string) => void,
  setCurrentStep: (step: EidFlowStep) => void,
  onEidFailure: (msg: string) => void
) => {
  let errorMessage = defaultMessage;
  if (axios.isAxiosError(err) && err.response?.data?.message) {
    errorMessage = err.response.data.message;
  } else if (err instanceof Error) {
    errorMessage = err.message;
  }
  console.error('eID process error:', err);
  setError(errorMessage);
  setCurrentStep(EidFlowStep.FAILED);
  onEidFailure(errorMessage);
};


enum EidFlowStep {
  IDENTIFICATION = 'identification',
  ATTRIBUTE_CONSENT = 'attribute_consent',
  PROCESSING = 'processing',
  COMPLETED = 'completed',
  FAILED = 'failed',
  USEID_INITIATION = 'useid_initiation', 
}

interface EidFlowContainerProps {
  onEidSuccess: (attributes: Record<string, any>) => void;
  onEidFailure: (error: string) => void;
}

export const EidFlowContainer: React.FC<EidFlowContainerProps> = ({ onEidSuccess, onEidFailure }) => {
  const [currentStep, setCurrentStep] = useState<EidFlowStep>(EidFlowStep.USEID_INITIATION);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [requestedAttributes, setRequestedAttributes] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [finalAttributes, setFinalAttributes] = useState<Record<string, any>>({});

  const getAllRequestedAttributes = useCallback(() => {
    const { personalData, address, documentData } = EID_CONFIG.REQUESTED_ATTRIBUTES;
    return [...personalData, ...address, ...documentData];
  }, []);

  const simulateEidClientCallback = useCallback(async (currentSessionId: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const mockBackendCallbackResponse = await axios.post(`${API_BASE_URL}/eid/callback`, {
        sessionId: currentSessionId,
        eidResponse: {
          status: 'SUCCESS',
          certificateChain: ['mock_cert_pem'],
          signature: 'mock_signature',
          signedData: 'mock_signed_data',
          nonce: 'mock_nonce_from_session',
          attributes: {
            givenNames: 'Max',
            familyName: 'Mustermann',
            dateOfBirth: '1990-01-01',
            address: 'Musterstrasse 1, 12345 Musterstadt',
            age: 30,
            gender: 'male',
          },
        },
      });

      if (mockBackendCallbackResponse.data.success) {
        setRequestedAttributes(Object.keys(mockBackendCallbackResponse.data.attributes));
        setCurrentStep(EidFlowStep.ATTRIBUTE_CONSENT);
        setFinalAttributes(mockBackendCallbackResponse.data.attributes);
      } else {
        setError(mockBackendCallbackResponse.data.message || 'eID authentication callback failed.');
        setCurrentStep(EidFlowStep.FAILED);
        onEidFailure(mockBackendCallbackResponse.data.message || 'eID authentication callback failed.');
      }
    } catch (err: any) {
      console.error('Error simulating eID client callback:', err);
      setError(err.response?.data?.message || err.message || 'Network error during eID callback simulation.');
      setCurrentStep(EidFlowStep.FAILED);
      onEidFailure(err.response?.data?.message || err.message || 'Network error during eID callback simulation.');
    } finally {
      setIsLoading(false);
    }
  }, [onEidFailure]);

  // Step 0: Initiate useID request to get a session ID
  const initiateUseIdRequest = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await axios.post(`${API_BASE_URL}/eid/initiate-useid`, {
        clientRedirectUrl: window.location.origin + '/eid-callback',
        requestedAttributes: getAllRequestedAttributes(),
      });

      if (response.data.success) {
        setSessionId(response.data.sessionId);
        setCurrentStep(EidFlowStep.IDENTIFICATION); // Move to IDENTIFICATION after useID initiation
      } else {
        setError(response.data.message || 'Failed to initiate useID session.');
        setCurrentStep(EidFlowStep.FAILED);
        onEidFailure(response.data.message || 'Failed to initiate useID session.');
      }
    } catch (err: any) {
      console.error('Error initiating useID session:', err);
      setError(err.response?.data?.message || err.message || 'Network error during useID initiation.');
      setCurrentStep(EidFlowStep.FAILED);
      onEidFailure(err.response?.data?.message || err.message || 'Network error during useID initiation.');
    } finally {
      setIsLoading(false);
    }
  }, [onEidFailure, getAllRequestedAttributes]);

  // Step 1: Start eID Authentication (now builds tcTokenUrl using an existing session)
const startEidIdentification = useCallback(async () => {
  if (!sessionId) {
    handleEidError(
      new Error(SESSION_ID_MISSING_ERROR),
      SESSION_ID_MISSING_ERROR,
      setError,
      setCurrentStep,
      onEidFailure
    );
    return;
  }

  setIsLoading(true);
  setError(null);
  try {
    const response = await axios.post(EID_START_ENDPOINT, {
      sessionId: sessionId,
      clientRedirectUrl: EID_CALLBACK_URL,
      requestedAttributes: getAllRequestedAttributes(),
    });

    if (response.data.success) {
      const tcTokenURL = response.data.tcTokenURL;
      console.log('eID authentication initiated. TC Token URL:', tcTokenURL);

      // IMPORTANT: In a production environment, uncomment the line below to redirect the user
      // to the eID client for actual authentication.
      // window.location.href = tcTokenURL;

      // For demonstration purposes, we simulate the eID client interaction
      // and transition to the consent step after a delay.
      setTimeout(() => {
        simulateEidClientCallback(sessionId);
      }, 2000);

      setCurrentStep(EidFlowStep.PROCESSING);
    } else {
      handleEidError(
        new Error(response.data.message || EID_START_FAILURE_MESSAGE),
        EID_START_FAILURE_MESSAGE,
        setError,
        setCurrentStep,
        onEidFailure
      );
    }
  } catch (err: unknown) { // Use 'unknown' for better type safety
    handleEidError(
      err,
      NETWORK_ERROR_MESSAGE,
      setError,
      setCurrentStep,
      onEidFailure
    );
  } finally {
    setIsLoading(false);
  }
}, [sessionId, onEidFailure, getAllRequestedAttributes, simulateEidClientCallback]);

  // Step 2: User consents to attributes
  const handleAttributeConsent = useCallback(async (selectedAttrs: string[]) => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await axios.post(`${API_BASE_URL}/eid/attributes/${sessionId}`, {
        attributeNames: selectedAttrs,
      });

      if (response.data.success) {
        setFinalAttributes(response.data.attributes);
        setCurrentStep(EidFlowStep.COMPLETED);
        onEidSuccess(response.data.attributes);
      } else {
        setError(response.data.message || 'Failed to finalize attribute consent.');
        setCurrentStep(EidFlowStep.FAILED);
        onEidFailure(response.data.message || 'Failed to finalize attribute consent.');
      }
    } catch (err: any) {
      console.error('Error handling attribute consent:', err);
      setError(err.response?.data?.message || err.message || 'Network error during attribute consent.');
      setCurrentStep(EidFlowStep.FAILED);
      onEidFailure(err.response?.data?.message || err.message || 'Network error during attribute consent.');
    } finally {
      setIsLoading(false);
    }
  }, [sessionId, onEidSuccess, onEidFailure]);

  const handleCancelEid = useCallback(() => {
    setError('eID process cancelled by user.');
    setCurrentStep(EidFlowStep.FAILED);
    onEidFailure('eID process cancelled.');
  }, [onEidFailure]);

  // Handle redirects from external eID client
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const callbackSessionId = urlParams.get('sessionId');
    const callbackStatus = urlParams.get('status');
    const callbackError = urlParams.get('error');

    if (callbackSessionId) {
      if (callbackStatus === 'success') {
        setCurrentStep(EidFlowStep.ATTRIBUTE_CONSENT);
      } else if (callbackStatus === 'failed') {
        setError(callbackError || 'eID authentication failed during external process.');
        setCurrentStep(EidFlowStep.FAILED);
        onEidFailure(callbackError || 'eID authentication failed during external process.');
      }
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }, [onEidFailure]);

  // Initial effect to start the useID flow when the component mounts
  useEffect(() => {
    if (currentStep === EidFlowStep.USEID_INITIATION) {
      initiateUseIdRequest();
    }
  }, [currentStep, initiateUseIdRequest]); // Re-run if currentStep changes to USEID_INITIATION or initiateUseIdRequest changes


  const renderStep = () => {
    switch (currentStep) {
      case EidFlowStep.USEID_INITIATION:
        return (
          <div className={styles.flowStep}>
            <h3>Initiating useID Session...</h3>
            <LoadingSpinner />
            <p>Please wait while we prepare your eID session.</p>
          </div>
        );
      case EidFlowStep.IDENTIFICATION:
        return (
          <UserIdentification
            onStartEid={startEidIdentification}
            isLoading={isLoading}
            error={error}
          />
        );
      case EidFlowStep.ATTRIBUTE_CONSENT:
        return (
          <AttributeConsent
            requestedAttributes={requestedAttributes}
            onConsent={handleAttributeConsent}
            onCancel={handleCancelEid}
            isLoading={isLoading}
            error={error}
          />
        );
      case EidFlowStep.PROCESSING:
        return (
          <div className={styles.flowStep}>
            <h3>Processing eID Data...</h3>
            <LoadingSpinner />
            <p>Please wait while we securely process your eID information.</p>
          </div>
        );
      case EidFlowStep.COMPLETED:
        return (
          <div className={styles.flowStep}>
            <h3>eID Authentication Successful!</h3>
            <p>Your identity has been verified and selected attributes shared.</p>
            <h4>Shared Attributes:</h4>
            <ul>
              {Object.entries(finalAttributes).map(([key, value]) => (
                <li key={key}><strong>{key}:</strong> {String(value)}</li>
              ))}
            </ul>
            <Button onClick={() => window.location.reload()}>Finish</Button>
          </div>
        );
      case EidFlowStep.FAILED:
        return (
          <div className={styles.flowStep}>
            <h3>eID Process Failed</h3>
            <p>{error || 'An error occurred during the eID process.'}</p>
            <Button onClick={() => window.location.reload()}>Try Again</Button>
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div className={styles.eidFlowContainer}>
      <h1 className={styles.flowTitle}>German eID Service</h1>
      {renderStep()}
    </div>
  );
};