import { UsersModule } from './../users/users.module';
import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { comparePassword, hashPassword } from 'src/utils/bcrypt';
import {
  ChangePasswordDto,
  ForgotPasswordDto,
  RegisterDto,
  ResendVerificationDto,
  ResetPasswordDto,
  VerifyDto,
} from './dto/auth.dto';
import { TokenType, VerifyStatus } from '@/constants/enums';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { RefreshToken } from './schemas/refreshToken.schema';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(RefreshToken.name)
    private readonly refreshTokenModel: Model<RefreshToken>,
    private usersService: UsersService,
    private jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async validateUser(email: string, pass: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      throw new NotFoundException(`User with email ${email} not found`);
    }

    if (user.verify === VerifyStatus.Unverified) {
      throw new BadRequestException('Tài khoản chưa được kích hoạt');
    }

    const isValidPassword = await comparePassword(pass, user.password);
    if (!isValidPassword) {
      throw new UnauthorizedException(`Password is not correct`);
    }

    return user;
  }

  private signVerifyToken({
    email,
    verify,
  }: {
    email: string;
    verify: VerifyStatus;
  }) {
    const payload = {
      email,
      token_type: TokenType.VerifyToken,
      verify,
    };

    return this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_VERIFY_TOKEN_SECRET_KEY'),
      expiresIn: this.configService.get<string>('JWT_VERIFY_TOKEN_EXPIRED'),
    });
  }

  private signForgotPasswordToken(email: string) {
    const payload = {
      email,
      token_type: TokenType.ForgotPasswordToken,
    };
    return this.jwtService.sign(payload, {
      secret: this.configService.get<string>(
        'JWT_FORGOT_PASSWORD_TOKEN_SECRET_KEY',
      ),
      expiresIn: this.configService.get<string>(
        'JWT_FORGOT_PASSWORD_TOKEN_EXPIRED',
      ),
    });
  }

  async verifyToken(token: string, key: string) {
    try {
      return await this.jwtService.verifyAsync(token, {
        secret: key,
      });
    } catch (e) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  async generateTokens(userId: string, username: string) {
    const payload = { sub: userId, username };

    const [access_token, refresh_token] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_ACCESS_TOKEN_SECRET_KEY'),
        expiresIn: this.configService.get<string>('JWT_ACCESS_TOKEN_EXPIRED'),
      }),
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_REFRESH_TOKEN_SECRET_KEY'),
        expiresIn: this.configService.get<string>('JWT_REFRESH_TOKEN_EXPIRED'),
      }),
    ]);

    return {
      access_token,
      refresh_token,
    };
  }

  async login(user: any): Promise<any> {
    const payload = { sub: user._id, username: user.email };

    const { access_token, refresh_token } = await this.generateTokens(
      payload.sub,
      payload.username,
    );

    const { iat, exp } = await this.verifyToken(
      refresh_token,
      this.configService.get<string>('JWT_REFRESH_TOKEN_SECRET_KEY'),
    );

    await this.refreshTokenModel.create({
      user_id: user._id,
      token: refresh_token,
      iat: new Date(iat * 1000),
      exp: new Date(exp * 1000),
    });

    return {
      access_token,
      refresh_token,
    };
  }

  async register(registerDto: RegisterDto): Promise<any> {
    const { email, password, confirm_password } = registerDto;

    if (password !== confirm_password) {
      throw new BadRequestException(
        'Password and confirm password do not match',
      );
    }
    const verify_token = await this.signVerifyToken({
      email,
      verify: VerifyStatus.Unverified,
    });
    return await this.usersService.register(registerDto, verify_token);
  }

  async verify(verifyDto: VerifyDto): Promise<any> {
    const { verify_token } = verifyDto;

    const { exp } = await this.verifyToken(
      verify_token,
      this.configService.get<string>('JWT_VERIFY_TOKEN_SECRET_KEY'),
    );

    if (exp < Math.floor(Date.now() / 1000)) {
      throw new UnauthorizedException('Verification token expired');
    }

    return this.usersService.verify(verifyDto);
  }

  async resendVerification(
    resendVerificationDto: ResendVerificationDto,
  ): Promise<any> {
    const { email } = resendVerificationDto;
    const verify_token = await this.signVerifyToken({
      email,
      verify: VerifyStatus.Unverified,
    });
    return await this.usersService.resendVerification(
      resendVerificationDto,
      verify_token,
    );
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<any> {
    const { email } = forgotPasswordDto;
    const forgot_password_token = await this.signForgotPasswordToken(email);
    return await this.usersService.forgotPassword(
      forgotPasswordDto,
      forgot_password_token,
    );
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<any> {
    const { forgot_password_token } = resetPasswordDto;

    const { exp } = await this.verifyToken(
      forgot_password_token,
      this.configService.get<string>('JWT_FORGOT_PASSWORD_TOKEN_SECRET_KEY'),
    );

    if (exp < Math.floor(Date.now() / 1000)) {
      throw new UnauthorizedException('Verification token expired');
    }

    return await this.usersService.resetPassword(resetPasswordDto);
  }

  async changePassword(
    changePasswordDto: ChangePasswordDto,
    user: any,
  ): Promise<any> {
    const { password, new_password, confirm_new_password } = changePasswordDto;
    const payload = { sub: user._id, username: user.email };
    if (new_password !== confirm_new_password) {
      throw new BadRequestException(
        'New password and confirm password do not match',
      );
    }

    const isValidPassword = await comparePassword(password, user.password);
    if (!isValidPassword) {
      throw new UnauthorizedException(`Current password is not correct`);
    }

    return await this.usersService.changePassword(changePasswordDto, payload);
  }
}
