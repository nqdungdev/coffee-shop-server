import { IsEmail, IsNotEmpty, IsOptional } from 'class-validator';

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

  @IsNotEmpty()
  confirm_password: string;

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

export class ForgotPasswordDto {
  @IsNotEmpty()
  email: string;
}

export class ResetPasswordDto {
  @IsNotEmpty()
  forgot_password_token: string;

  @IsNotEmpty()
  user_id: string;

  @IsNotEmpty()
  new_password: string;
}

export class ChangePasswordDto {
  @IsNotEmpty()
  password: string;

  @IsNotEmpty()
  new_password: string;

  @IsNotEmpty()
  confirm_new_password: string;
}
