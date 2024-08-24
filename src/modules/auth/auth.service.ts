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
import { RegisterDto, ResendVerificationDto, VerifyDto } from './dto/auth.dto';
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

  private signForgotPasswordToken({
    userId,
    verify,
  }: {
    userId: string;
    verify: VerifyStatus;
  }) {
    const payload = {
      userId,
      token_type: TokenType.ForgotPasswordToken,
      verify,
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
    const { email } = registerDto;
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
    resendVerification: ResendVerificationDto,
  ): Promise<any> {
    const { email } = resendVerification;
    const verify_token = await this.signVerifyToken({
      email,
      verify: VerifyStatus.Unverified,
    });
    return await this.usersService.resendVerification(
      resendVerification,
      verify_token,
    );
  }

  // async register(registerDto: RegisterDto) {
  //   const { email, password, name, date_of_birth, phone } = registerDto;

  //   const email_verify_token = await this.signEmailVerifyToken({
  //     email,
  //     verify: VerifyStatus.Unverified,
  //   });

  //   await databaseService.users.insertOne(
  //     new User({
  //       ...payload,
  //       _id: user_id,
  //       username: `user${user_id.toString()}`,
  //       email_verify_token,
  //       date_of_birth: new Date(payload.date_of_birth),
  //       password: hashPassword(payload.password),
  //     }),
  //   );

  //   const [access_token, refresh_token] = await this.signAccessAndRefreshToken({
  //     user_id: user_id.toString(),
  //     verify: UserVerifyStatus.Unverified,
  //   });

  //   const { iat, exp } = await this.decodeRefreshToken(refresh_token);

  //   await databaseService.refreshTokens.insertOne(
  //     new RefreshToken({
  //       user_id: new ObjectId(user_id),
  //       token: refresh_token,
  //       iat,
  //       exp,
  //     }),
  //   );

  //   return { access_token, refresh_token };
  // }
}
