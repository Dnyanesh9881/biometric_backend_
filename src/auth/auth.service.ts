import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UserService } from '../user/user.service';
import { JwtUtil } from 'src/common/utils/jwt.util';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

@Injectable()
export class AuthService {
  constructor(private userService: UserService) {}
  private challengeStore = {};
  // Normal Registration (with email and password)
  async register(
    username: string,
    email: string,
    password: string,
  ): Promise<{ token: string; user: any }> {
    const user = await this.userService.create(username, email, password);
    const token = JwtUtil.generateToken({ email: user.email });
    return { token, user };
  }

  // Normal Login (with email and password)
  async login(
    email: string,
    password: string,
  ): Promise<{ token: string; user: any }> {
    const user = await this.userService.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const token = JwtUtil.generateToken({ email: user.email });
    return { token, user };
  }

  // Generate WebAuthn registration options
  async bioGenerateRegistrationOptions(email: string): Promise<any> {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    console.log(user);
    const options = await generateRegistrationOptions({
      rpName: 'My Localhost Machine',
      rpID: 'localhost', // Change this to your domain when in production
      //   userID: user._id.toString(), // User ID from your DB
      userName: user.email, // User email or username
      // attestationType: 'none', // Set 'none' to skip attestation requirements
      // timeout: 30000, // Timeout for the registration process
    });
    console.log(options);

    // Store the challenge in the database or in-memory store to verify later
    this.challengeStore[email] = options.challenge;

    return options;
  }

  // Verify WebAuthn registration response
  async verifyRegistrationResponse(
    email: string,
    credential: any,
  ): Promise<{ token: string }> {
    console.log('emai;l', email, 'credentials', credential);
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    console.log('user', user);
    console.log(this.challengeStore);
    // Fetch the expected challenge from your storage (database)
    const verification = await verifyRegistrationResponse({
      expectedChallenge: this.challengeStore[email], // The challenge previously stored during registration
      expectedOrigin: 'http://localhost:3000', // Change to your front-end URL in production
      expectedRPID: 'localhost',
      response: credential,
    });
    console.log(verification);
    if (!verification.verified) {
      throw new UnauthorizedException('Invalid registration response');
    }
    // userStore[userId].passkey = verificationResult.registrationInfo
    //  await this.userService.savePassKey(email, verification.registrationInfo);
    const passKey = {
      id: verification.registrationInfo.credentialID,
      publicKey: verification.registrationInfo.credentialPublicKey,
      counter: verification.registrationInfo.counter,
      deviceType: verification.registrationInfo.credentialDeviceType,
      backedUp: verification.registrationInfo.credentialBackedUp,
      transport: credential.transports, // Adjust this as necessary
    };

    const data = await this.userService.savePassKey(email, passKey);

    // Save the credential information to the user profile (e.g., in MongoDB)
    // await this.userService.addWebAuthnCredential(user._id, verification.registrationInfo);
    console.log(data);
    // Generate a JWT token for authenticated session
    const token = JwtUtil.generateToken({ email: user.email });
    return { token };
  }

  //   // Generate WebAuthn authentication options (for login)
  async bioGenerateAuthenticationOptions(email: string): Promise<any> {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const options =await generateAuthenticationOptions({
      rpID: 'localhost', // Your domain
      allowCredentials: [
        {
          id: user.passKeys[0].credentialID,
          // type: "public-key",
          transports: user.passKeys[0].transport,
        },
      ],
    });

    // Store the challenge for verification later
    // await this.userService.saveChallenge(user._id, options.challenge)
    this.challengeStore[email] = options.challenge;
    console.log(options);
    // this.challengeStore[email] = options.challenge;
    return options;
  }

  //   // Verify WebAuthn authentication response
  async verifyAuthenticationResponse(
    email: string,
    credential: any,
  ): Promise<{ token: string }> {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    console.log('credential', credential);
    // Retrieve the expected challenge from your storage (database)
    const expectedChallenge = this.challengeStore[email];

    const result = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: expectedChallenge,
      expectedOrigin: 'http://localhost:3000', // Change to your client URL
      expectedRPID: 'localhost',
      authenticator: {
        credentialID: user.passKeys[0].credentialID,
        credentialPublicKey: user.passKeys[0].publicKey,
        counter: user.passKeys[0].counter,
        // transports: user.passKeys[0].transport,
      }, // Find the user's authenticator
    });

    if (!result.verified) {
      throw new UnauthorizedException('Invalid authentication response');
    }

    // Successful authentication, issue a JWT token
    const token = JwtUtil.generateToken({ email: user.email });
    return { token };
  }
}
