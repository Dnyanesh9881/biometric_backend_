// src/user/user.service.ts
import { Injectable, ConflictException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import { User, UserDocument } from '../schemas/user.schema';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class UserService {
  constructor(@InjectModel("userModel") private userModel: Model<UserDocument>) {}

  async create(username: string, email: string, password: string): Promise<User> {
    const existingUser = await this.userModel.findOne({ email: email });
    if (existingUser) {
      throw new ConflictException('Email already in use');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new this.userModel({ username, email, password: hashedPassword });
    return user.save();
  }

  async findByEmail(email: string): Promise<User | null> {
    return await this.userModel.findOne({ email }).exec();
  }
  async savePassKey(email: string, passKey: any) {
    return await this.userModel.findOneAndUpdate(
      { email: email },
      {
        $push: {
          passKeys: {
            credentialID: passKey.id,
            publicKey: Array.from(passKey.publicKey), // Convert Uint8Array to array of numbers
            counter: passKey.counter,
            credentialType: 'public-key', // Assuming this is constant based on your data
            deviceType: passKey.deviceType,
            backedUp: passKey.backedUp,
            transport: passKey.transport,
          },
        },
      },
      { new: true } // This returns the updated document
    );
  }
  

  async validateUser(email: string, password: string): Promise<User | null> {
    const user = await this.findByEmail(email);
    if (user && (await bcrypt.compare(password, user.password))) {
      return user;
    }
    return null;
  }
}
