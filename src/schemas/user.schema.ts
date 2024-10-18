// src/user/schemas/user.schema.ts
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type UserDocument = HydratedDocument<User>;

@Schema()
export class WebAuthnCredential {
  @Prop()
  credentialID: string;

  @Prop()
  publicKey:Buffer; // Alternatively, this can be stored as a Buffer

  @Prop()
  counter: number;

  @Prop()
  credentialType: string;

  @Prop()
  deviceType: string;

  @Prop()
  backedUp: boolean;

  @Prop()
  transport: []; // Assuming transport is a string, adjust if it's different
}

export const WebAuthnCredentialSchema = SchemaFactory.createForClass(WebAuthnCredential);

@Schema()
export class User {
  @Prop({ required: true, unique: true })
  username: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop()
  password: string; // Optional, for password-based login

  // Changed passKeys to an array to store multiple credentials
  @Prop({ type: [WebAuthnCredentialSchema], default: [] }) 
  passKeys: WebAuthnCredential[]; // Store multiple WebAuthn credentials
}

export const UserSchema = SchemaFactory.createForClass(User);
