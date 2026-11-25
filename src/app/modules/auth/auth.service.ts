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

import {
  ILoginPayload,
  IRegisterPayload,
  IRegistrationData,
  IResetPasswordPayload,
  IVerifyEmailPayload,
} from "./auth.interface";

const generateOTP = () => {
  return randomInt(100000, 1000000).toString();
};

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

  return {
    accessToken,
    refreshToken,
  };
};

const registerUser = async (payload: IRegisterPayload) => {
  const name = payload.name.trim();
  const email = payload.email.toLowerCase().trim();

  const existingUser = await prisma.user.findUnique({
    where: {
      email,
    },
  });

  if (existingUser) {
    throw new AppError(
      httpStatus.CONFLICT,
      "User already exists with this email",
    );
  }

  const hashedPassword = await bcrypt.hash(
    payload.password,
    Number(config.bcrypt_salt_rounds),
  );

  const otp = generateOTP();

  const otpKey = `notwise:register:otp:${email}`;
  const registrationDataKey = `notwise:register:data:${email}`;

  const registrationData: IRegistrationData = {
    name,
    email,
    password: hashedPassword,
  };

  await redisClient.set(otpKey, otp, {
    EX: 300,
  });

  await redisClient.set(registrationDataKey, JSON.stringify(registrationData), {
    EX: 300,
  });

  // console.log("REGISTER EMAIL:", email);
  // console.log("REGISTER DATA KEY:", registrationDataKey);
  // console.log(
  //   "REGISTER SAVED DATA:",
  //   await redisClient.get(registrationDataKey),
  // );
  // console.log("REGISTER DATA TTL:", await redisClient.ttl(registrationDataKey));

  try {
    const html = await ejs.renderFile(
      path.join(process.cwd(), "src/app/template/registration-user-otp.ejs"),
      {
        name,
        otp,
      },
    );

    await transporter.sendMail({
      from: config.email_sender,
      to: email,
      subject: "Verify Your Email - Notwise",
      html,
    });
  } catch (error) {
    await redisClient.del(otpKey);
    await redisClient.del(registrationDataKey);

    throw new AppError(
      httpStatus.INTERNAL_SERVER_ERROR,
      "Failed to send verification email",
    );
  }

  return {
    message: "A verification OTP has been sent to your email",
  };
};

const verifyEmail = async (payload: IVerifyEmailPayload) => {
  const email = payload.email.toLowerCase().trim();

  const otpKey = `notwise:register:otp:${email}`;
  const registrationDataKey = `notwise:register:data:${email}`;

  const savedOtp = await redisClient.get(otpKey);
  const savedRegistrationData = await redisClient.get(registrationDataKey);

  if (!savedOtp || !savedRegistrationData) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      "OTP expired or registration data not found",
    );
  }

  if (savedOtp !== payload.otp) {
    throw new AppError(httpStatus.BAD_REQUEST, "Invalid OTP");
  }

  const registrationData: IRegistrationData = JSON.parse(savedRegistrationData);

  const existingUser = await prisma.user.findUnique({
    where: {
      email,
    },
  });

  if (existingUser) {
    await redisClient.del(otpKey);
    await redisClient.del(registrationDataKey);

    throw new AppError(
      httpStatus.CONFLICT,
      "User already exists with this email",
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

  await redisClient.del(otpKey);
  await redisClient.del(registrationDataKey);

  try {
    const html = await ejs.renderFile(
      path.join(process.cwd(), "src/app/template/student-welcome-email.ejs"),
      {
        name: user.name,
        email: user.email,
      },
    );

    await transporter.sendMail({
      from: config.email_sender,
      to: user.email,
      subject: "Welcome to Notwise!",
      html,
    });
  } catch (error) {
    console.error("Welcome email sending failed:", error);
  }

  const tokens = generateTokens({
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  });

  const { password, ...userWithoutPassword } = user;

  return {
    user: userWithoutPassword,
    ...tokens,
  };
};

const resendVerificationOtp = async (email: string) => {
  console.log("===== RESEND FUNCTION STARTED =====");
  console.log("RECEIVED EMAIL:", email);

  email = email.toLowerCase().trim();

  const registrationDataKey = `notwise:register:data:${email}`;
  const otpKey = `notwise:register:otp:${email}`;

  // console.log("RESEND EMAIL:", email);
  // console.log("RESEND DATA KEY:", registrationDataKey);
  // console.log("REDIS READY:", redisClient.isReady);

  const savedRegistrationData = await redisClient.get(
    registrationDataKey,
  );

  // console.log("RESEND SAVED DATA:", savedRegistrationData);

  // console.log(
  //   "RESEND DATA TTL:",
  //   await redisClient.ttl(registrationDataKey),
  // );

  if (!savedRegistrationData) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      "Registration session expired. Please register again",
    );
  }

  const registrationData: IRegistrationData = JSON.parse(
    savedRegistrationData,
  );

  const otp = generateOTP();

  await redisClient.set(otpKey, otp, {
    EX: 300,
  });

  await redisClient.expire(registrationDataKey, 300);

  try {
    const html = await ejs.renderFile(
      path.join(
        process.cwd(),
        "src/app/template/registration-user-otp.ejs",
      ),
      {
        name: registrationData.name,
        otp,
      },
    );

    await transporter.sendMail({
      from: config.email_sender,
      to: email,
      subject: "New Email Verification OTP - Notwise",
      html,
    });
  } catch (error) {
    console.error("RESEND OTP EMAIL ERROR:", error);

    await redisClient.del(otpKey);

    throw new AppError(
      httpStatus.INTERNAL_SERVER_ERROR,
      "Failed to resend verification OTP",
    );
  }

  return {
    message: "A new verification OTP has been sent to your email",
  };
};
   
const loginUser = async (payload: ILoginPayload) => {
  const email = payload.email.toLowerCase().trim();

  const user = await prisma.user.findUnique({
    where: {
      email,
    },
  });

  if (!user || user.deletedAt) {
    throw new AppError(httpStatus.NOT_FOUND, "User not found");
  }

  if (user.status === "BLOCKED") {
    throw new AppError(httpStatus.FORBIDDEN, "Your account has been blocked");
  }

  if (!user.isEmailVerified) {
    throw new AppError(httpStatus.FORBIDDEN, "Please verify your email first");
  }

  if (!user.password) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      "Please login using your registered authentication method",
    );
  }

  const isPasswordMatched = await bcrypt.compare(
    payload.password,
    user.password,
  );

  if (!isPasswordMatched) {
    throw new AppError(httpStatus.UNAUTHORIZED, "Invalid email or password");
  }

  const tokens = generateTokens({
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  });

  const { password, ...userWithoutPassword } = user;

  return {
    user: userWithoutPassword,
    ...tokens,
  };
};
   
const getMe = async (userId: string) => {
  const user = await prisma.user.findUnique({
    where: {
      id: userId,
    },
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
    throw new AppError(httpStatus.NOT_FOUND, "User not found");
  }

  if (user.status === "BLOCKED") {
    throw new AppError(httpStatus.FORBIDDEN, "Your account has been blocked");
  }

  return user;
};
   
const refreshToken = async (token: string) => {
  const verifiedToken = jwtUtils.verifyToken(token, config.refresh_secret);

  if (!verifiedToken.success) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      "Invalid or expired refresh token",
    );
  }

  const decodedData = verifiedToken.data as JwtPayload;

  const userId = decodedData.userId as string;

  const user = await prisma.user.findUnique({
    where: {
      id: userId,
    },
  });

  if (!user || user.deletedAt) {
    throw new AppError(httpStatus.NOT_FOUND, "User not found");
  }

  if (user.status === "BLOCKED") {
    throw new AppError(httpStatus.FORBIDDEN, "Your account has been blocked");
  }

  const tokens = generateTokens({
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  });

  return tokens;
};

const forgotPassword = async (email: string) => {
  email = email.toLowerCase().trim();

  const user = await prisma.user.findUnique({
    where: {
      email,
    },
  });

  const genericMessage = {
    message:
      "If an account exists with this email, a password reset OTP has been sent",
  };

  if (!user || user.deletedAt || !user.password) {
    return genericMessage;
  }

  const otpKey = `notwise:forgot-password:otp:${email}`;

  const otp = generateOTP();

  await redisClient.set(otpKey, otp, {
    EX: 300,
  });

  try {
    const html = await ejs.renderFile(
      path.join(process.cwd(), "src/app/template/forget-password-otp.ejs"),
      {
        name: user.name,
        otp,
      },
    );

    await transporter.sendMail({
      from: config.email_sender,
      to: email,
      subject: "Password Reset OTP - Notwise",
      html,
    });
  } catch (error) {
    await redisClient.del(otpKey);

    throw new AppError(
      httpStatus.INTERNAL_SERVER_ERROR,
      "Failed to send password reset OTP",
    );
  }

  return genericMessage;
};

const resendForgotPasswordOtp = async (email: string) => {
  email = email.toLowerCase().trim();

  const user = await prisma.user.findUnique({
    where: {
      email,
    },
  });

  const genericMessage = {
    message:
      "If an account exists with this email, a password reset OTP has been sent",
  };

  if (!user || user.deletedAt || !user.password) {
    return genericMessage;
  }

  const otpKey = `notwise:forgot-password:otp:${email}`;

  const otp = generateOTP();

  await redisClient.set(otpKey, otp, {
    EX: 300,
  });

  try {
    const html = await ejs.renderFile(
      path.join(process.cwd(), "src/app/template/forget-password-otp.ejs"),
      {
        name: user.name,
        otp,
      },
    );

    await transporter.sendMail({
      from: config.email_sender,
      to: email,
      subject: "New Password Reset OTP - Notwise",
      html,
    });
  } catch (error) {
    await redisClient.del(otpKey);

    throw new AppError(
      httpStatus.INTERNAL_SERVER_ERROR,
      "Failed to resend password reset OTP",
    );
  }

  return genericMessage;
};

const resetPassword = async (payload: IResetPasswordPayload) => {
  const email = payload.email.toLowerCase().trim();

  const otpKey = `notwise:forgot-password:otp:${email}`;

  const savedOtp = await redisClient.get(otpKey);

  if (!savedOtp) {
    throw new AppError(httpStatus.BAD_REQUEST, "OTP expired or not found");
  }

  if (savedOtp !== payload.otp) {
    throw new AppError(httpStatus.BAD_REQUEST, "Invalid OTP");
  }

  const user = await prisma.user.findUnique({
    where: {
      email,
    },
  });

  if (!user || user.deletedAt) {
    throw new AppError(httpStatus.NOT_FOUND, "User not found");
  }

  if (!user.password) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      "Password reset is not available for this account",
    );
  }

  const hashedPassword = await bcrypt.hash(
    payload.newPassword,
    Number(config.bcrypt_salt_rounds),
  );

  await prisma.user.update({
    where: {
      id: user.id,
    },
    data: {
      password: hashedPassword,
    },
  });

  await redisClient.del(otpKey);

  try {
    const html = await ejs.renderFile(
      path.join(process.cwd(), "src/app/template/reset-password-otp.ejs"),
      {
        name: user.name,
      },
    );

    await transporter.sendMail({
      from: config.email_sender,
      to: email,
      subject: "Password Reset Successful - Notwise",
      html,
    });
  } catch (error) {
    console.error("Password reset confirmation email failed:", error);
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
