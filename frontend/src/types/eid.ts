/**
 * @file Contains type definitions for eID-related data and processes.
 */

/**
 * Interface representing the initial response from starting an eID authentication.
 */
export interface EidAuthResponse {
  transactionId: string;
  redirectUrl?: string; // URL to an eID client or for further steps if needed
  statusUrl: string; // URL to poll for status updates
  message: string;
}

/**
 * Interface representing the response from polling the eID authentication status.
 */
export interface EidStatusResponse {
  status: 'IN_PROGRESS' | 'SUCCESS' | 'FAILED' | 'PENDING' | 'USER_CONSENT_REQUIRED' | 'CARD_NOT_FOUND';
  attributes?: EidAttributes; // eID attributes if authentication is successful
  errorMessage?: string;
  nextStepUrl?: string; // If there are further steps in the eID flow
  progress?: {
    currentStep: number;
    maxSteps: number;
    description: string;
  };
}

/**
 * Interface representing the structured eID attributes returned upon successful authentication.
 * This should align with the attributes requested in EID_CONFIG and TR-03124.
 */
export interface EidAttributes {
  // Personal Data (according to TR-03124)
  givenNames?: string;
  familyName?: string;
  birthName?: string;
  dateOfBirth?: string; // YYYY-MM-DD
  placeOfBirth?: string;
  nationality?: string;
  gender?: 'M' | 'F' | 'X'; // MALE, FEMALE, DIVERSE

  // Address Data
  street?: string;
  houseNumber?: string;
  zipCode?: string;
  city?: string;
  country?: string;

  // Document Data
  documentType?: string; // e.g., "ID Card"
  issuingAuthority?: string;
  documentNumber?: string;
  dateOfIssue?: string; // YYYY-MM-DD
  dateOfExpiry?: string; // YYYY-MM-DD
  can?: string; // Card Access Number (for PACE)
}