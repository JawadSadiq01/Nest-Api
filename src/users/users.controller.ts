import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { Request } from 'express';
import { JwtGuard } from 'src/auth/guard';

@Controller('users')
export class UsersController {

  @UseGuards(JwtGuard)
  @Get('me')
  getMe(@Req() req: Request) {
    return {
      currentUser: req.user
    }
  }
}
