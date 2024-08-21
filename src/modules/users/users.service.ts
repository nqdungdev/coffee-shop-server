import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { isValidObjectId, Model } from 'mongoose';
import { hashPassword } from 'src/utils/bcrypt';
import { RegisterDto } from '../auth/dto/auth.dto';
import { MailService } from '../mail/mail.service';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
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

  async register(registerDto: RegisterDto): Promise<any> {
    const { email, password, name } = registerDto;

    //check email
    const isExist = await this.isEmailExist(email);
    if (isExist === true) {
      throw new BadRequestException(
        `Email đã tồn tại: ${email}. Vui lòng sử dụng email khác.`,
      );
    }

    //hash password
    const hashedPassword = await hashPassword(password);
    const user = await this.userModel.create({
      name,
      email,
      password: hashedPassword,
      isActive: false,
      // codeExpired: dayjs().add(30, 'seconds')
    });

    // await this.mailService.sendUserConfirmation(user, token);

    //send email
    this.mailService.sendUserConfirmation(user, '1234');
    //trả ra phản hồi
    return {
      _id: user._id,
    };
  }
}
