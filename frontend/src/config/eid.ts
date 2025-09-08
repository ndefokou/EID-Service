// Configuration for German eID specific parameters

export const EID_CONFIG = {
  // Relying Party (RP) parameters - these would typically be registered with the eID server
  RP_ID: 'your-relying-party-id', // Unique ID for your application
  RP_NAME: 'German eID Service', // Name of your application

  // eID server callback URL (where the eID server redirects after authentication)
  // This should match a route in your frontend application
  EID_CALLBACK_URL: `${window.location.origin}/eid-callback`,

  // Attributes requested from the eID card (example attributes)
  // These should correspond to the attributes your application needs and is authorized to request
  REQUESTED_ATTRIBUTES: {
    personalData: ['GivenName', 'FamilyName', 'DateOfBirth', 'PlaceOfBirth'],
    address: ['Street', 'HouseNumber', 'ZipCode', 'City', 'Country'],
    documentData: ['DocumentType', 'IssuingState', 'DateOfExpiry'],
  },

  // Polling interval for eID status (in milliseconds)
  POLLING_INTERVAL: 3000, // Poll every 3 seconds

  // Maximum number of polling attempts before timing out
  MAX_POLLING_ATTEMPTS: 20, // 20 attempts * 3 seconds = 60 seconds timeout
};