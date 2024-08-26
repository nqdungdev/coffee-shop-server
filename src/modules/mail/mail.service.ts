import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { Mail } from './schemas/mail.schema';

@Injectable()
export class MailService {
  constructor(private mailerService: MailerService) {}

  async sendUserConfirmation({
    user,
    subject,
    url,
  }: {
    user: Mail;
    subject: string;
    url: string;
  }) {
    await this.mailerService.sendMail({
      to: user.email,
      subject: subject,
      template: 'confirmation',
      context: {
        name: user?.name ?? user.email,
        url,
      },
    });
  }
}
