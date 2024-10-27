import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class LoginUserDto {
  username: string;
  email: string;

  @IsNotEmpty()
  @MinLength(6)
  password: string;
}
