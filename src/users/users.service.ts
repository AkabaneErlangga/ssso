// user/user.service.ts
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  async updateRefreshToken(userId: string, refreshToken: string) {
    const hashedToken = await bcrypt.hash(refreshToken, 10);
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        refreshToken: {
          create: {
            token: hashedToken,
            //set expiresAt to 30 days from now
            expiresAt: new Date(
              new Date().getTime() + 30 * 24 * 60 * 60 * 1000,
            ),
          },
        },
      },
    });
  }

  async findOne(userId: string) {
    return this.prisma.user.findUnique({
      where: { id: userId },
      include: { refreshToken: true },
    });
  }

  async findUserByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email },
    });
  }
}
