import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { isValidObjectId, Model } from 'mongoose';
import { hashPassword } from 'src/utils/bcrypt';
import {
  RegisterDto,
  ResendVerificationDto,
  VerifyDto,
} from '../auth/dto/auth.dto';
import { MailService } from '../mail/mail.service';
import { VerifyStatus } from '@/constants/enums';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    private mailService: MailService,
  ) {}

  isEmailExist = async (email: string) => {
    const user = await this.userModel.exists({ email });
    return user ? true : false;
  };

  async findByEmail(email: string) {
    return this.userModel.findOne({ email });
  }

  async create(createUserDto: CreateUserDto) {
    const { name, email, password, phone, address, image } = createUserDto;

    const isExist = await this.isEmailExist(email);
    if (isExist) {
      throw new BadRequestException(
        'Email đã tồn tại, vui lòng sử dụng email khác',
      );
    }
    const hashedPassword = await hashPassword(password);

    const user = await this.userModel.create({
      name,
      email,
      password: hashedPassword,
      isActive: false,
      phone,
      address,
      image,
    });
    return { _id: user._id };
  }

  findAll(query: string) {
    return `This action returns all users`;
  }

  async findOne(id: string) {
    if (!isValidObjectId(id)) {
      throw new BadRequestException(`${id} is not a valid ObjectId`);
    }

    const user = await this.userModel.findById(id).exec();
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    return user;
  }

  async update(id: string, updateUserDto: UpdateUserDto) {
    if (!isValidObjectId(id)) {
      throw new BadRequestException(`${id} is not a valid ObjectId`);
    }
    const { email, password, ...allowedUpdates } = updateUserDto;

    const updatedUser = await this.userModel
      .findByIdAndUpdate(id, allowedUpdates, {
        new: true,
      })
      .exec();

    if (!updatedUser) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }

    return updatedUser;
  }

  async remove(id: string) {
    if (!isValidObjectId(id)) {
      throw new BadRequestException(`${id} is not a valid ObjectId`);
    }

    return await this.userModel.deleteOne({ _id: id }).exec();
  }

  async register(registerDto: RegisterDto, verify_token: string): Promise<any> {
    const { email, password } = registerDto;

    const isExist = await this.isEmailExist(email);
    if (isExist) {
      throw new BadRequestException(
        `Email đã tồn tại: ${email}. Vui lòng sử dụng email khác.`,
      );
    }

    const hashedPassword = await hashPassword(password);

    const user = await this.userModel.create({
      ...registerDto,
      password: hashedPassword,
      verify: VerifyStatus.Unverified,
      verify_token,
    });

    this.mailService.sendUserConfirmation(user, verify_token);

    return {
      _id: user._id,
    };
  }

  async verify(verifyDto: VerifyDto): Promise<any> {
    const { user_id, verify_token } = verifyDto;
    const user = await this.userModel.findOne({
      _id: user_id,
      verify_token,
    });
    if (!user) {
      throw new UnauthorizedException('Invalid verification token');
    }

    await this.userModel.updateOne(
      { _id: user_id },
      { verify_token: '', verify: VerifyStatus.Verified },
    );

    // // Delete the token after successful verification
    // await this.verificationTokenModel.deleteOne({ _id: storedToken._id });

    return { message: 'Email verified successfully' };
  }

  async resendVerification(
    resendVerificationDto: ResendVerificationDto,
    verify_token: string,
  ): Promise<any> {
    const { email } = resendVerificationDto;

    const user = await this.findByEmail(email);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Kiểm tra xem email đã được xác thực chưa
    if (user.verify === VerifyStatus.Verified) {
      throw new ConflictException('Email is already verified');
    }

    await this.userModel.updateOne(
      { _id: user._id },
      { verify_token, verify: VerifyStatus.Unverified },
    );

    this.mailService.sendUserConfirmation(user, verify_token);

    return { message: 'Verification email resent successfully' };
  }
}
