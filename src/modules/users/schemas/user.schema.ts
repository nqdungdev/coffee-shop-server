import { VerifyStatus } from '@/constants/enums';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { IsEnum } from 'class-validator';
import { HydratedDocument } from 'mongoose';

export type UserDocument = HydratedDocument<User>;

@Schema({ timestamps: true })
export class User {
  @Prop()
  name: string;

  @Prop()
  email: string;

  @Prop()
  password: string;

  @Prop()
  date_of_birth: Date;

  @Prop()
  phone: string;

  @Prop()
  address: string;

  @Prop()
  image: string;

  @Prop({ default: 'USERS' })
  role: string;

  @Prop({ default: 'LOCAL' })
  accountType: string;

  @Prop()
  verify_token?: string;

  @Prop()
  forgot_password_token?: string;

  @Prop({ type: Number, enum: VerifyStatus, default: VerifyStatus.Unverified })
  @IsEnum(VerifyStatus)
  verify?: VerifyStatus;
}

export const UserSchema = SchemaFactory.createForClass(User);
