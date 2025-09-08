import { Schema, model, Document } from 'mongoose';

/**
 * Represents an eID authentication session.
 * This interface defines the structure of an eID session document stored in MongoDB.
 */
export interface IEidSession extends Document {
  sessionId: string;
  userId: string | null; // Null if the user is not logged in during eID auth
  status: 'INITIATED' | 'USEID_INITIATED' | 'PENDING' | 'COMPLETED' | 'FAILED' | 'EXPIRED';
  statusDetail?: string; // More descriptive status message
  nonce: string; // Unique value to prevent replay attacks
  clientRedirectUrl: string; // The URL to redirect the frontend to after eID process
  requestedAttributes: string[]; // List of attributes requested from the eID card
  attributes: object; // Stores the attributes received from the eID card
  rawEidResponse?: string; // Stores the raw response from the eID client
  tcTokenURL?: string; // URL for the eID client to obtain the TC Token
  refreshAddress?: string; // Refresh URL for redirecting the caller to the eService
  loaRequested?: string; // Level of Assurance requested
  loaResult?: string; // Actual Level of Assurance achieved
  eidTypeRequested?: string[]; // Specific eID types requested/allowed
  eidTypeResult?: string; // Actual eID type used
  ageVerificationRequested?: boolean; // Whether age verification was requested
  ageVerificationResult?: boolean; // Result of age verification
  communityIdRequested?: string; // Community ID for location verification
  communityIdResult?: boolean; // Result of location verification
  requestCounter?: number; // Counter for getResult calls to prevent replay attacks
  transactionAttestationRequest?: object; // Optional: context for transaction attestation
  transactionAttestationResponse?: object; // Response for transaction attestation
  operationsAllowedByUser?: string[]; // Data groups and functions allowed by user
  eCardServerAddress?: string; // Address of the eCard-API-Framework component

  createdAt: Date;
  updatedAt: Date;
  expiresAt?: Date; // Optional expiry time for the session
}

/**
 * Mongoose Schema for the EidSession.
 * Defines the structure and validation rules for eID session documents.
 */
const EidSessionSchema = new Schema<IEidSession>({
  sessionId: { type: String, required: true, unique: true, index: true },
  userId: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  status: { type: String, required: true, enum: ['INITIATED', 'USEID_INITIATED', 'PENDING', 'COMPLETED', 'FAILED', 'EXPIRED'], default: 'INITIATED' },
  statusDetail: { type: String },
  nonce: { type: String, required: true },
  clientRedirectUrl: { type: String, required: true },
  requestedAttributes: [{ type: String }],
  attributes: { type: Schema.Types.Mixed, default: {} },
  rawEidResponse: { type: String },
  loaRequested: { type: String },
  loaResult: { type: String },
  eidTypeRequested: [{ type: String }],
  eidTypeResult: { type: String },
  ageVerificationRequested: { type: Boolean, default: false },
  ageVerificationResult: { type: Boolean },
  communityIdRequested: { type: String },
  communityIdResult: { type: Boolean },
  requestCounter: { type: Number, default: 0 },
  transactionAttestationRequest: { type: Schema.Types.Mixed },
  transactionAttestationResponse: { type: Schema.Types.Mixed },
  operationsAllowedByUser: [{ type: String }],
  eCardServerAddress: { type: String },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, index: { expires: '1h' } }, // Sessions expire after 1 hour by default
});

// Update `updatedAt` field on every save
EidSessionSchema.pre('save', function (next) {
  this.updatedAt = new Date();
  next();
});

/**
 * Mongoose Model for the EidSession.
 * Provides an interface for interacting with the 'EidSession' collection in MongoDB.
 */
export const EidSession = model<IEidSession>('EidSession', EidSessionSchema);