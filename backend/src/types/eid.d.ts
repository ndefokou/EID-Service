// This file will contain global type definitions relevant to the eID process,
// such as structures for eID session data, attribute requests, etc.

/**
 * Interface representing the structure of an eID attribute to be requested.
 * This aligns with the requirements of TR-03124.
 */
export interface EidAttributeRequest {
  readonly oid: string; // Object Identifier of the attribute
  readonly required: boolean; // Whether the attribute is mandatory
  readonly status: 'optional' | 'required' | 'read'; // Status of the attribute in the request
  readonly refreshAddress?: string; // Optional: URL to refresh the attribute
}

/**
 * Interface for the data returned by the eID server after successful authentication
 * and attribute release. This will contain the actual personal data.
 */
export interface EidServerResponseAttributes {
  // These are example attributes. Actual attributes will depend on the eID server
  // and the requested attribute profile.
  DateOfBirth?: string;
  FamilyName?: string;
  GivenNames?: string;
  PlaceOfBirth?: string;
  Nationality?: string;
  ArtisticName?: string;
  AcademicTitle?: string;
  Address?: {
    Street?: string;
    HouseNumber?: string;
    ZipCode?: string;
    City?: string;
    Country?: string;
  };
  // Add other attributes as defined in TR-03124 and your specific attribute profiles
}

/**
 * Interface representing the structure of an eID session.
 * This can be used to store ongoing eID transaction state.
 */
export interface EidSessionData {
  sessionId: string;
  nonce: string;
  eIdClientBaseUrl: string; // The URL the eID client should redirect to
  requiredAttributes: EidAttributeRequest[];
  // Other session-specific data like timestamp, status, etc.
  createdAt: Date;
  updatedAt: Date;
  status: 'STARTED' | 'REDIRECTED' | 'SUCCESS' | 'FAILED' | 'EXPIRED';
  userId?: string; // Link to a user if authenticated
  rawEidResponse?: EidServerResponseAttributes; // Raw attributes from eID server
}

/**
 * Type representing the configuration for a specific eID service provider (Relying Party).
 */
export interface RelyingPartyConfig {
  rpId: string; // The unique ID of the Relying Party
  rpName: string; // Human-readable name
  rpUrl: string; // Base URL of the Relying Party
  eacCertificates: string[]; // List of EAC certificate PEMs
  supportedAttributeProfiles: string[]; // OIDs or names of supported attribute profiles
  // Add other RP-specific configurations
}