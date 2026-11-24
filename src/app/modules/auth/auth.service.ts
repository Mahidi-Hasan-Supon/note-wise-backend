import bcrypt from "bcrypt";
import ejs from "ejs";
import path from "path";
import { randomInt } from "crypto";
import type { JwtPayload } from "jsonwebtoken";
import httpStatus from "http-status";

import config from "../../config";
import { prisma } from "../../lib/prisms";
import { redisClient } from "../../lib/redis";
import { transporter } from "../../lib/nodemailer";
import { AppError } from "../../utiles/appError";
import { jwtUtils } from "../../utiles/jwt";
import { ILoginPayload, IRegisterPayload, IRegistrationData, IResetPasswordPayload, IVerifyEmailPayload } from "./auth.interface";


// Redis keys
const registrationOtpKey = (email: string) => `notwise:register:otp:${email}`;

const registrationDataKey = (email: string) => `notwise:register:data:${email}`;

const forgotPasswordOtpKey = (email: string) =>
  `notwise:forgot-password:otp:${email}`;

// Generate OTP
const generateOTP = () => randomInt(100000, 1000000).toString();

// Generate tokens
const generateTokens = (user: {
  id: string;
  name: string;
  email: string;
  role: "STUDENT" | "ADMIN";
}) => {
  const jwtPayload = {
    userId: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  };

  const accessToken = jwtUtils.createToken(
    jwtPayload,
    config.access_secret,
    config.access_expires_in as string,
  );

  const refreshToken = jwtUtils.createToken(
    jwtPayload,
    config.refresh_secret,
    config.refresh_expires_in as string,
  );

  return { accessToken, refreshToken };
};

// Send registration OTP email
const sendRegistrationOtpEmail = async (
  name: string,
  email: string,
  otp: string,
) => {
  const html = await ejs.renderFile(
    path.join(process.cwd(), "src/app/templates/registration-user-otp.ejs"),
    { name, otp },
  );

  await transporter.sendMail({
    from: config.email_sender,
    to: email,
    subject: "Verify your Notwise account",
    html,
  });
};

// 1. Register User
const registerUser = async (payload: IRegisterPayload) => {
  const name = payload.name.trim();
  const email = payload.email.trim().toLowerCase();    
      
  const existingUser = await prisma.user.findUnique({    
    where: { email },
  });

  if (existingUser) {
    throw new AppError(
      httpStatus.CONFLICT,
      "An account already exists with this email",
    );
  }
   
  const hashedPassword = await bcrypt.hash(
    payload.password,
    Number(config.bcrypt_salt_rounds),
  );

  const otp = generateOTP();

  const registrationData: IRegistrationData = {
    name,
    email,
    password: hashedPassword,
  };

  const otpKey = registrationOtpKey(email);
  const dataKey = registrationDataKey(email);
   
  await redisClient.set(otpKey, otp, { EX: 300 });
  await redisClient.set(dataKey, JSON.stringify(registrationData), {
    EX: 300,
  });

  try {
    await sendRegistrationOtpEmail(name, email, otp);
  } catch (error) {
    await redisClient.del([otpKey, dataKey]);
    console.error("Registration email error:", error);

    throw new AppError(
      httpStatus.INTERNAL_SERVER_ERROR,
      "Failed to send verification email",
    );
  }

  return {
    email,
    message: "OTP sent to your email. Please verify your email",
  };
};

// 2. Verify Email
const verifyEmail = async (payload: IVerifyEmailPayload) => {
  const email = payload.email.trim().toLowerCase();

  const otpKey = registrationOtpKey(email);
  const dataKey = registrationDataKey(email);

  const savedOtp = await redisClient.get(otpKey);
  const savedData = await redisClient.get(dataKey);

  if (!savedOtp || !savedData) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      "OTP expired. Please register again",
    );
  }

  if (savedOtp !== payload.otp) {
    throw new AppError(httpStatus.BAD_REQUEST, "Invalid OTP");
  }

  const registrationData = JSON.parse(savedData) as IRegistrationData;

  const existingUser = await prisma.user.findUnique({
    where: { email },
  });

  if (existingUser) {
    await redisClient.del([otpKey, dataKey]);

    throw new AppError(
      httpStatus.CONFLICT,
      "An account already exists with this email",
    );
  }

  const user = await prisma.user.create({
    data: {
      name: registrationData.name,
      email: registrationData.email,
      password: registrationData.password,
      role: "STUDENT",
      authProvider: "CREDENTIAL",
      status: "ACTIVE",
      isEmailVerified: true,
    },
  });

  await redisClient.del([otpKey, dataKey]);

  // Welcome email
  try {
    const html = await ejs.renderFile(
      path.join(process.cwd(), "src/app/templates/student-welcome-email.ejs"),
      { name: user.name },
    );

    await transporter.sendMail({
      from: config.email_sender,
      to: user.email,
      subject: "Welcome to Notwise",
      html,
    });
  } catch (error) {
    console.error("Welcome email error:", error);
  }

  const { accessToken, refreshToken } = generateTokens(user);
  const { password, ...userWithoutPassword } = user;

  return {
    accessToken,
    refreshToken,
    user: userWithoutPassword,
  };
};  

// 3. Resend Verification OTP
const resendVerificationOtp = async (email: string) => {
  email = email.trim().toLowerCase();

  const savedData = await redisClient.get(registrationDataKey(email));

  if (!savedData) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      "Registration session expired. Please register again",
    );
  }

  const registrationData = JSON.parse(savedData) as IRegistrationData;

  const otp = generateOTP();

  await redisClient.set(registrationOtpKey(email), otp, {
    EX: 300,
  });

  try {
    await sendRegistrationOtpEmail(registrationData.name, email, otp);
  } catch (error) {
    await redisClient.del(registrationOtpKey(email));
    console.error("Resend verification email error:", error);

    throw new AppError(
      httpStatus.INTERNAL_SERVER_ERROR,
      "Failed to resend verification OTP",
    );
  }

  return {
    message: "Verification OTP resent successfully",
  };
}; 

// 4. Login User
const loginUser = async (payload: ILoginPayload) => {
  const email = payload.email.trim().toLowerCase();

  const user = await prisma.user.findUnique({
    where: { email },
  });

  if (!user || user.deletedAt) {
    throw new AppError(httpStatus.UNAUTHORIZED, "Invalid email or password");
  }

  if (user.status === "BLOCKED") {
    throw new AppError(httpStatus.FORBIDDEN, "Your account has been blocked");
  }

  if (!user.isEmailVerified) {
    throw new AppError(httpStatus.FORBIDDEN, "Please verify your email first");
  }

  if (!user.password) {
    throw new AppError(httpStatus.UNAUTHORIZED, "Invalid email or password");
  }

  const isPasswordMatched = await bcrypt.compare(
    payload.password,
    user.password,
  );

  if (!isPasswordMatched) {
    throw new AppError(httpStatus.UNAUTHORIZED, "Invalid email or password");
  }

  const { accessToken, refreshToken } = generateTokens(user);
  const { password, ...userWithoutPassword } = user;

  return {
    accessToken,
    refreshToken,
    user: userWithoutPassword,
  };
};

// 5. Get Me
const getMe = async (userId: string) => {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      name: true,
      email: true,
      imageUrl: true,
      imagePublicId: true,
      role: true,
      status: true,
      authProvider: true,
      isEmailVerified: true,
      createdAt: true,
      updatedAt: true,
      deletedAt: true,
    },
  });

  if (!user || user.deletedAt) {
    throw new AppError(httpStatus.UNAUTHORIZED, "Please login again");
  }

  if (user.status === "BLOCKED") {
    throw new AppError(httpStatus.FORBIDDEN, "Your account has been blocked");
  }

  return user;
};

// 6. Refresh Token
const refreshToken = async (token: string) => {
  const verified = jwtUtils.verifyToken(token, config.refresh_secret);

  if (!verified.success) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      "Invalid or expired refresh token",
    );
  }

  const { userId } = verified.data as JwtPayload;

  const user = await prisma.user.findUnique({
    where: { id: userId as string },
  });

  if (!user || user.deletedAt) {
    throw new AppError(httpStatus.UNAUTHORIZED, "Please login again");
  }

  if (user.status === "BLOCKED") {
    throw new AppError(httpStatus.FORBIDDEN, "Your account has been blocked");
  }

  const { accessToken, refreshToken } = generateTokens(user);

  return { accessToken, refreshToken };
};
  
// 7. Forgot Password
const forgotPassword = async (email: string) => {
  email = email.trim().toLowerCase();

  const user = await prisma.user.findUnique({
    where: { email },
  });

  if (!user || user.deletedAt || !user.password) {
    return {
      message: "If the account exists, a password reset OTP will be sent",
    };
  }

  const otp = generateOTP();

  await redisClient.set(forgotPasswordOtpKey(email), otp, {
    EX: 300,
  });

  try {
    const html = await ejs.renderFile(
      path.join(process.cwd(), "src/app/templates/forget-password-otp.ejs"),
      { name: user.name, otp },
    );

    await transporter.sendMail({
      from: config.email_sender,
      to: email,
      subject: "Notwise password reset OTP",
      html,
    });
  } catch (error) {
    await redisClient.del(forgotPasswordOtpKey(email));
    console.error("Forgot password email error:", error);

    throw new AppError(
      httpStatus.INTERNAL_SERVER_ERROR,
      "Failed to send password reset OTP",
    );
  }

  return {
    message: "Password reset OTP sent successfully",
  };
};

// 8. Resend Forgot Password OTP
const resendForgotPasswordOtp = async (email: string) => {
  return forgotPassword(email);
};

// 9. Reset Password
const resetPassword = async (payload: IResetPasswordPayload) => {
  const email = payload.email.trim().toLowerCase();
  const otpKey = forgotPasswordOtpKey(email);

  const savedOtp = await redisClient.get(otpKey);

  if (!savedOtp) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      "OTP expired. Please request a new OTP",
    );
  }

  if (savedOtp !== payload.otp) {
    throw new AppError(httpStatus.BAD_REQUEST, "Invalid OTP");
  }

  const user = await prisma.user.findUnique({
    where: { email },
  });

  if (!user || user.deletedAt || !user.password) {
    throw new AppError(httpStatus.NOT_FOUND, "User not found");
  }

  const hashedPassword = await bcrypt.hash(
    payload.newPassword,
    Number(config.bcrypt_salt_rounds),
  );

  await prisma.user.update({
    where: { id: user.id },
    data: { password: hashedPassword },
  });

  await redisClient.del(otpKey);

  try {
    const html = await ejs.renderFile(
      path.join(process.cwd(), "src/app/templates/reset-password-otp.ejs"),
      { name: user.name },
    );

    await transporter.sendMail({
      from: config.email_sender,
      to: user.email,
      subject: "Notwise password changed",
      html,
    });
  } catch (error) {
    console.error("Password reset confirmation email error:", error);
  }

  return {
    message: "Password reset successfully",
  };
};

export const authService = {
  registerUser,
  verifyEmail,
  resendVerificationOtp,
  loginUser,
  getMe,
  refreshToken,
  forgotPassword,
  resendForgotPasswordOtp,
  resetPassword,
};
