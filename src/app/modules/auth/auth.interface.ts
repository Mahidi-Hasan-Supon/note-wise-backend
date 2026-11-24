
// export interface IRegister {
//   name: string;
//   email: string;
//   password: string;
// }

// export interface ILogin {
//   email: string;
//   password: string;
// }

// export interface IVerifyEmail {
//   email: string;
//   otp: string;
// }

// export interface IResendOTP {
//   email: string;
// }

// export interface IForgotPassword {
//   email: string;
// }

// export interface IResetPassword {
//   email: string;
//   otp: string;
//   newPassword: string;
// }

// export interface IRefreshToken {
//   refreshToken: string;
// }
// Types



export interface IRegisterPayload {
  name: string;
  email: string;
  password: string;
}

export interface ILoginPayload {
  email: string;
  password: string;
}

export interface IVerifyEmailPayload {
  email: string;
  otp: string;
}

export interface IResetPasswordPayload {
  email: string;
  otp: string;
  newPassword: string;
}

export interface IRegistrationData {
  name: string;
  email: string;
  password: string;
}
