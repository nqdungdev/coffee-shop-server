export enum VerifyStatus {
  Unverified,
  Verified,
  Banned,
}

export enum TokenType {
  AccessToken,
  RefreshToken,
  ForgotPasswordToken,
  VerifyToken,
}

export enum MediaType {
  Image,
  Video,
  HLS,
}

export enum MediaTypeQuery {
  Image = 'image',
  Video = 'video',
}
