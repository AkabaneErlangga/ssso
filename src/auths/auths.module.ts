// auth/auth.module.ts
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthsService } from './auths.service';
import { AuthsController } from './auths.controller';
import { JwtAccessStrategy } from './strategies/jwt-access.strategy';
import { JwtRefreshStrategy } from './strategies/jwt-refresh.strategy';
import { UsersService } from '../users/users.service';
import { PrismaService } from '../prisma/prisma.service';

@Module({
  imports: [JwtModule.register({})],
  providers: [
    AuthsService,
    JwtAccessStrategy,
    JwtRefreshStrategy,
    UsersService,
    PrismaService,
  ],
  controllers: [AuthsController],
})
export class AuthsModule {}
