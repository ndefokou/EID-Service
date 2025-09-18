import dotenv from 'dotenv';

dotenv.config();

export const EID_CONFIG = {
  // Relying Party Configuration
  RP_ID: process.env.EID_RP_ID || 'localhost',
  RP_CALLBACK_URL: process.env.EID_RP_CALLBACK_URL || 'http://localhost:3001/api/eid/callback',
  RP_CERTIFICATE_PATH: process.env.EID_RP_CERTIFICATE_PATH || './certificates/rp/rp-certificate.pem',
  RP_PRIVATE_KEY_PATH: process.env.EID_RP_PRIVATE_KEY_PATH || './certificates/eid_server/eid-server-private-key.pem',
  RP_PRIVATE_KEY_PASS: process.env.EID_RP_PRIVATE_KEY_PASS || '', // Added for encrypted private keys

  // eID Client Configuration
  // IMPORTANT: In production, this URL must point to the actual eID client.
  EID_CLIENT_BASE_URL: process.env.EID_CLIENT_BASE_URL || 'http://127.0.0.1:24727/eID-Client',
  
  // SAML Specific Configuration for TR-03124 Compliance
  EID_SERVER_SAML_ENDPOINT: process.env.EID_SERVER_SAML_ENDPOINT || 'https://localhost:3000/',
  EID_SERVER_SAML_CERT_PATH: process.env.EID_SERVER_SAML_CERT_PATH || './certificates/eid_server/eid-server-certificate.pem',
  RP_SAML_ENTITY_ID: process.env.EID_RP_SAML_ENTITY_ID || 'http://localhost:3001/saml/metadata',
  RP_ACS_URL: process.env.EID_RP_ACS_URL || 'http://localhost:3001/api/eid/saml/acs',
  TR_03124_SAML_METADATA_URL: process.env.TR_03124_SAML_METADATA_URL || 'https://eid-server.example.com/saml/metadata',

  // eID Server Configuration
  // IMPORTANT: In production, this URL must point to the actual eID server.
  EID_SERVER_BASE_URL: process.env.EID_SERVER_BASE_URL || 'https://localhost:3000/',
  // IMPORTANT: Ensure these certificate paths are correctly resolved in your production environment.
  EID_SERVER_CERTIFICATE_PATH: process.env.EID_SERVER_CERTIFICATE_PATH || './certificates/eid_server/eid-server-certificate.pem',
  EID_SERVER_PRIVATE_KEY_PATH: process.env.EID_SERVER_PRIVATE_KEY_PATH || './certificates/eid_server/eid-server-private-key.pem',
  EID_SERVER_TIMEOUT: parseInt(process.env.EID_SERVER_TIMEOUT || '10000', 10), // in milliseconds
  DEFAULT_ECARD_SERVER_ADDRESS: process.env.EID_DEFAULT_ECARD_SERVER_ADDRESS || 'https://default-ecard-server.example.com',

  // Retry Mechanism for External Requests
  MAX_RETRIES: parseInt(process.env.EID_MAX_RETRIES || '3', 10),
  RETRY_DELAY: parseInt(process.env.EID_RETRY_DELAY || '1000', 10), // 1 second

  // Blacklist Service Configuration
  BLACKLIST_SERVICE_URL: process.env.EID_BLACKLIST_SERVICE_URL || 'http://localhost:3002/blacklist',

  // Trust Anchor Configuration
  // IMPORTANT: Ensure these certificate paths are correctly resolved in your production environment.
  TRUST_ANCHOR_BVA_SERVER_CERT: process.env.TRUST_ANCHOR_BVA_SERVER_CERT || './certificates/trust_anchors/bva-server-certificate.pem',
  TRUST_ANCHOR_BVA_ECARD_PROFILES: process.env.TRUST_ANCHOR_BVA_ECARD_PROFILES || './certificates/trust_anchors/bva-eid-server-ecard-profiles.pem',

  // TR-03124 Configuration
  // IMPORTANT: Ensure these certificate paths are correctly resolved in your production environment.
  TR_03124_EAC_CA_CERT: process.env.TR_03124_EAC_CA_CERT || './certificates/tr-03124/tr-03124-eac-ca.pem',
  TR_03124_ECARD_API_SERVER_TEST_CERT: process.env.TR_03124_ECARD_API_SERVER_TEST_CERT || './certificates/tr-03124/tr-03124-ecard-api-server-test.pem',
  TR_03124_SERVER_CERTIFICATE_PATH: process.env.TR_03124_SERVER_CERTIFICATE_PATH || './certificates/tr-03124/tr-03124-server-certificate.pem',

  // eID Attributes to Request
  REQUESTED_ATTRIBUTES: (process.env.EID_REQUESTED_ATTRIBUTES || 'givenNames,familyName,dateOfBirth').split(','),

  // Session and State Management
  // IMPORTANT: In production, EID_SESSION_SECRET must be set via an environment variable. Do NOT use the default.
  SESSION_SECRET: process.env.EID_SESSION_SECRET || 'supersecret_eidsession_key',
  SESSION_TIMEOUT: parseInt(process.env.EID_SESSION_TIMEOUT || '3600000', 10), // 1 hour in milliseconds

  // Frontend Redirect URLs
  FRONTEND_ERROR_REDIRECT_URL: process.env.FRONTEND_ERROR_REDIRECT_URL || 'http://localhost:8080/eid-error',
  FRONTEND_SUCCESS_REDIRECT_URL: process.env.FRONTEND_SUCCESS_REDIRECT_URL || 'http://localhost:8080/eid-success',
  FRONTEND_CALLBACK_URL: process.env.FRONTEND_CALLBACK_URL || 'http://localhost:8081/eid-callback',

  // Supported eID Service Capabilities
  SUPPORTED_EID_TYPES: (process.env.EID_SUPPORTED_EID_TYPES || 'Person,AgeVerification,Address').split(','),
  SUPPORTED_LOA: (process.env.EID_SUPPORTED_LOA || 'Low,Substantial,High').split(','),

  // Encryption and Hashing
  // IMPORTANT: In production, EID_ENCRYPTION_KEY must be a strong, randomly generated key set via an environment variable. Do NOT use the default.
  ENCRYPTION_KEY: process.env.EID_ENCRYPTION_KEY || 'aVeryStrongEncryptionKeyForSensitiveData!', // 32 bytes for AES-256
  HASH_SALT_ROUNDS: parseInt(process.env.EID_HASH_SALT_ROUNDS || '10', 10),
  // Placeholder for blacklisted eID card identifiers
  BLACKLISTED_CARD_IDENTIFIERS: (process.env.EID_BLACKLISTED_CARD_IDENTIFIERS || '').split(',').filter(Boolean),
};