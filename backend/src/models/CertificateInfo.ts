import { Schema, model, Document } from 'mongoose';

/**
 * Interface representing the structure of a Certificate Information document.
 * This will store details about certificates used in the eID process,
 * such as the server certificate, root certificates, etc.
 */
export interface ICertificateInfo extends Document {
  alias: string; // A unique alias for the certificate (e.g., 'eID-Server-Root-CA', 'TLS-Client-Cert')
  type: string;  // Type of certificate (e.g., 'X.509', 'TR-03124-Auth')
  pem: string;   // The certificate content in PEM format
  issuer?: string; // The issuer distinguished name
  subject?: string; // The subject distinguished name
  validFrom?: Date; // NotBefore date
  validTo?: Date;   // NotAfter date
  fingerprint?: string; // SHA-256 fingerprint of the certificate
  createdAt: Date;
  updatedAt: Date;
}

const CertificateInfoSchema: Schema = new Schema({
  alias: { type: String, required: true, unique: true, trim: true },
  type: { type: String, required: true, trim: true },
  pem: { type: String, required: true },
  issuer: { type: String, required: false },
  subject: { type: String, required: false },
  validFrom: { type: Date, required: false },
  validTo: { type: Date, required: false },
  fingerprint: { type: String, required: false, unique: true, sparse: true }, // Sparse to allow multiple nulls
}, {
  timestamps: true, // Adds createdAt and updatedAt fields
});

// Ensure that if a fingerprint is provided, it must be unique.
// If not provided (undefined/null), uniqueness is not enforced.
CertificateInfoSchema.index({ fingerprint: 1 }, { unique: true, sparse: true });

export const CertificateInfo = model<ICertificateInfo>('CertificateInfo', CertificateInfoSchema);