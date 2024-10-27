// auth/auth.controller.ts
import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import { AuthsService } from './auths.service';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RegisterUserDto } from './dtos/register-user.dto';
import { LoginUserDto } from './dtos/login-user.dto';
import { UsersService } from 'src/users/users.service';

@Controller('auth')
export class AuthsController {
  constructor(
    private authsService: AuthsService,
    private userService: UsersService,
  ) {}

  @Post('register')
  async register(@Body() registerUserDto: RegisterUserDto) {
    return this.authsService.register(registerUserDto);
  }

  @Post('login')
  async login(@Body() loginUserDto: LoginUserDto) {
    const user = await this.userService.findUserByEmail(loginUserDto.email);
    return this.authsService.login(user);
  }

  @UseGuards(JwtRefreshGuard)
  @Post('refresh')
  async refreshToken(@Req() req) {
    const userId = req.user.userId;
    const refreshToken = req.user.refreshToken;
    return {
      accessToken: await this.authsService.refreshAccessToken(
        userId,
        refreshToken,
      ),
    };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(@Req() req) {
    await this.authsService.logout(req.user.userId); // Clear refresh token
    return { message: 'Logged out' };
  }
}
