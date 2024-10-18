import { Controller, Post, Body, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Request, Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // Endpoint for user registration
  @Post('register')
  async register(
    @Body('username') username: string,
    @Body('email') email: string,
    @Body('password') password: string,
  ) {
    console.log("username",username)
    return this.authService.register(username, email, password);
  }

  // Endpoint for user login via email/password
  @Post('login')
  async login(
    @Body('email') email: string,
    @Body('password') password: string,
  ) {
    return this.authService.login(email, password);
  }

  // Endpoint for generating WebAuthn registration options
    @Post('generate-registration-options')
  async generateRegistrationOptions(
    @Body('email') email: string,
  ): Promise<any> {
    return this.authService.bioGenerateRegistrationOptions(email);
  }

//   // Endpoint for verifying WebAuthn registration response
  @Post('verify-registration-response')
  async verifyRegistrationResponse(
    @Body('email') email: string,
    @Body('credential') credential: any,
  ): Promise<{ token: string }> {
    return this.authService.verifyRegistrationResponse(email,credential);
  }

  // Endpoint for generating WebAuthn authentication options
  @Post('generate-authentication-options')
  async generateAuthenticationOptions(
    @Body('email') email: string,
  ): Promise<any> {
    return this.authService.bioGenerateAuthenticationOptions(email);
  }

//   // Endpoint for verifying WebAuthn authentication response
  @Post('verify-authentication-response')
  async verifyAuthenticationResponse(
    @Body('credential') credential: any,
    @Body('email') email: string,
  ): Promise<{ token: string }> {
    return this.authService.verifyAuthenticationResponse(email, credential);
  }
}
