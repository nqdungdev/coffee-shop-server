import { Types } from 'mongoose';

export class Mail {
  _id: Types.ObjectId;
  email: string;
  name: string;
}
