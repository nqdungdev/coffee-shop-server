import { IsEmail, IsNotEmpty, IsOptional } from 'class-validator';
import { Types } from 'mongoose';

export class LoginDto {
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  password: string;
}

export class RegisterDto {
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  password: string;

  @IsOptional()
  name?: string;

  @IsOptional()
  date_of_birth?: Date;

  @IsOptional()
  phone?: string;
}

export class VerifyDto {
  @IsNotEmpty()
  verify_token: string;

  @IsNotEmpty()
  user_id: string;
}

export class ResendVerificationDto {
  @IsNotEmpty()
  email: string;
}
