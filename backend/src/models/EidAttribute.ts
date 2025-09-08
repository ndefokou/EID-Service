import { Schema, model, Document } from 'mongoose';

/**
 * Interface representing the structure of an eID Attribute document.
 * This model defines the attributes that can be requested from the eID card
 * during an authentication session, according to TR-03124.
 */
export interface IEidAttribute extends Document {
  name: string;      // The canonical name of the attribute (e.g., 'GivenName', 'FamilyName', 'DateOfBirth')
  oid: string;       // The Object Identifier (OID) of the attribute, as per TR-03124
  required: boolean; // Whether this attribute is required for a specific eID service
  scope?: string;    // Optional: Defines the scope or context for which this attribute is used
  description?: string; // Human-readable description of the attribute
  createdAt: Date;
  updatedAt: Date;
}

const EidAttributeSchema: Schema = new Schema({
  name: { type: String, required: true, unique: true, trim: true },
  oid: { type: String, required: true, unique: true, trim: true },
  required: { type: Boolean, default: false },
  scope: { type: String, required: false, trim: true },
  description: { type: String, required: false },
}, {
  timestamps: true, // Adds createdAt and updatedAt fields
});

export const EidAttribute = model<IEidAttribute>('EidAttribute', EidAttributeSchema);