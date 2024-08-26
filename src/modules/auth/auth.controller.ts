import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  HttpCode,
  HttpStatus,
  UseGuards,
  Request,
  Redirect,
  Query,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './passport/local-auth.guard';
import { Public } from 'src/decorator/customize';
import {
  ChangePasswordDto,
  ForgotPasswordDto,
  RegisterDto,
  ResendVerificationDto,
} from './dto/auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('login')
  @UseGuards(LocalAuthGuard)
  login(@Request() req) {
    return this.authService.login(req.user);
  }

  @Public()
  @Post('register')
  register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Public()
  @Get('verify')
  @Redirect('http://localhost:3000', HttpStatus.OK)
  verify(@Query('id') user_id: string, @Query('token') verify_token: string) {
    return this.authService.verify({ user_id, verify_token });
  }

  @Public()
  @Post('resend-verification')
  resendVerification(@Body() resendVerificationDto: ResendVerificationDto) {
    return this.authService.resendVerification(resendVerificationDto);
  }

  @Post('forgot-password')
  @Public()
  forgotPassword(@Body('email') forgotPasswordDto: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordDto);
  }

  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  async resetPassword(
    @Query('id') user_id: string,
    @Query('token') forgot_password_token: string,
    @Body('new_password') new_password: string,
  ) {
    await this.authService.resetPassword({
      user_id,
      forgot_password_token,
      new_password,
    });
    return { message: 'Password reset successfully' };
  }

  @Post('change-password')
  changePassword(@Body() changePasswordDto: ChangePasswordDto, @Request() req) {
    return this.authService.changePassword(changePasswordDto, req.user);
  }

  @Get('profile')
  getProfile(@Request() req) {
    return req.user;
  }

  // @Post('refresh-token')
  // async refreshToken(@Body('refreshToken') refreshToken: string) {
  //   return this.authService.refreshTokens(refreshToken);
  // }
}
