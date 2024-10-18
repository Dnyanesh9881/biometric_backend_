// src/user/user.controller.ts
import { Controller, Get, Req, UseGuards,  } from '@nestjs/common';
import { Request } from 'express';
import { AuthGuard } from 'src/common/middleware/auth.middleware';

@Controller('user')
export class UserController {
  @UseGuards(AuthGuard)
  @Get('profile')
  getProfile(@Req() req: Request) {
    return req.body.user;
  }
}
