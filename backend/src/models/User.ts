import { Schema, model, Document } from 'mongoose';
import bcrypt from 'bcryptjs';
import { JWT_CONFIG } from '../../config/jwt'; // Adjusted path

export interface IUser extends Document {
  _id: import('mongoose').Types.ObjectId; // Explicitly define _id
  username: string;
  email: string;
  password?: string; // Optional for users authenticated via eID or other means
  eIdAttributes?: Record<string, any>; // Stores attributes received from eID
  refreshToken?: string;
  comparePassword: (candidatePassword: string) => Promise<boolean>;
}

const UserSchema = new Schema<IUser>({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  password: {
    type: String,
    minlength: 6,
  },
  eIdAttributes: {
    type: Schema.Types.Mixed, // Store various eID attributes
  },
  refreshToken: {
    type: String,
  },
}, { timestamps: true });

// Hash password before saving
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password') || !this.password) {
    return next();
  }
  try {
    const salt = await bcrypt.genSalt(10); // Using 10 salt rounds as default
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error: any) {
    next(error);
  }
});

// Compare password method
UserSchema.methods.comparePassword = async function (candidatePassword: string): Promise<boolean> {
  if (!this.password) {
    return false;
  }
  return bcrypt.compare(candidatePassword, this.password);
};

export const User = model<IUser>('User', UserSchema);