// src/auth/auth.service.ts

import { ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../users/users.service';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { RegisterUserDto } from './dtos/register-user.dto';
import { User } from '@prisma/client';

@Injectable()
export class AuthsService {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
    private usersService: UsersService,
    private prisma: PrismaService,
  ) {}

  /**
   * Helper function to get refresh token expiry time in milliseconds
   */
  private getRefreshTokenExpiryTime(): number {
    const expiry = this.configService.get<string>('JWT_REFRESH_EXPIRATION');
    const duration = parseInt(expiry) * 24 * 60 * 60 * 1000; // Convert days to milliseconds
    return isNaN(duration) ? 7 * 24 * 60 * 60 * 1000 : duration; // Default to 7 days if invalid
  }

  /**
   * Generate a new access token for the user
   */
  private getAccessToken(userId: string): string {
    const payload = { sub: userId };
    return this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
      expiresIn: this.configService.get<string>('JWT_ACCESS_EXPIRATION'),
    });
  }

  /**
   * Generate a new refresh token for the user
   */
  private getRefreshToken(userId: string): string {
    const payload = { sub: userId };
    return this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRATION'),
    });
  }

  /**
   * Log in a user and issue access and refresh tokens
   */
  async login(user: User) {
    const accessToken = this.getAccessToken(user.id);
    const refreshToken = this.getRefreshToken(user.id);

    // Hash the refresh token before storing it in the database
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    await this.prisma.refreshToken.create({
      data: {
        token: hashedRefreshToken,
        userId: user.id,
        expiresAt: new Date(Date.now() + this.getRefreshTokenExpiryTime()),
      },
    });

    return { accessToken, refreshToken };
  }

  /**
   * Refresh the access token if a valid refresh token is provided
   */
  async refreshAccessToken(
    userId: string,
    refreshToken: string,
  ): Promise<string> {
    // Retrieve stored hashed refresh token
    const storedToken = await this.prisma.refreshToken.findFirst({
      where: {
        userId,
        expiresAt: { gt: new Date() }, // Check that the token has not expired
      },
    });

    // Verify that the stored hashed refresh token matches the provided refresh token
    if (
      !storedToken ||
      !(await bcrypt.compare(refreshToken, storedToken.token))
    ) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    // Issue a new access token
    return this.getAccessToken(userId);
  }

  /**
   * Log out the user by deleting their refresh token(s)
   */
  async logout(userId: string, refreshToken?: string) {
    if (refreshToken) {
      // Delete a specific refresh token (single session logout)
      const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
      await this.prisma.refreshToken.deleteMany({
        where: {
          userId,
          token: hashedRefreshToken,
        },
      });
    } else {
      // Delete all refresh tokens for the user (global logout)
      await this.prisma.refreshToken.deleteMany({
        where: { userId },
      });
    }
  }

  async register(registerUserDto: RegisterUserDto) {
    const { username, email, password } = registerUserDto;

    // Check if the user already exists
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });
    if (existingUser) {
      throw new ConflictException('Email is already registered');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create the user
    const newUser = await this.prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
      },
    });

    return newUser;
  }
}
