import bcrypt from "bcrypt";
import ejs from "ejs";
import path from "path";
import { randomInt } from "crypto";
import httpStatus from "http-status";

import config from "../../config";
import { prisma } from "../../lib/prisms";
import { redisClient } from "../../lib/redis";
import { transporter } from "../../lib/nodemailer";
import { AppError } from "../../utiles/appError";
import { jwtUtils } from "../../utiles/jwt";
import { IRegister } from "./auth.interface";

// Redis keys
const getRegistrationOTPKey = (email: string) =>
  `notwise:register:otp:${email}`;

const getRegistrationDataKey = (email: string) =>
  `notwise:register:data:${email}`;

// 1. Register user
const register = async (payload: IRegister) => {
  const name = payload.name.trim();
  const email = payload.email.trim().toLowerCase();

  // Check existing user
  const existingUser = await prisma.user.findUnique({
    where: { email },
  });

  if (existingUser) {
    throw new AppError(
      httpStatus.CONFLICT,
      "An account already exists with this email",
    );
  }

  // Hash password
  const hashedPassword = await bcrypt.hash(
    payload.password,
    Number(config.bcrypt_salt_rounds),
  );

  // Generate 6 digit OTP
  const otp = randomInt(100000, 1000000).toString();

  const registrationData: IRegister = {
    name,
    email,
    password: hashedPassword,
  };

  const otpKey = getRegistrationOTPKey(email);
  const dataKey = getRegistrationDataKey(email);

  // Store OTP and registration data for 5 minutes
  await redisClient.set(otpKey, otp, { EX: 300 });
  await redisClient.set(dataKey, JSON.stringify(registrationData), {
    EX: 300,
  });

  try {
    const html = await ejs.renderFile(
      path.join(process.cwd(), "src/app/templates/registration-user-otp.ejs"),
      {
        name,
        otp,
      },
    );

    await transporter.sendMail({
      from: config.email_sender,
      to: email,
      subject: "Verify your Notwise account",
      html,
    });
  } catch (error) {
    await redisClient.del([otpKey, dataKey]);

    console.error("Registration OTP email error:", error);

    throw new AppError(
      httpStatus.INTERNAL_SERVER_ERROR,
      "Failed to send verification email",
    );
  }

  return {
    email,
    message: "A verification OTP has been sent to your email",
  };
};

// 2. Verify email
const verifyEmail = async (payload: { email: string; otp: string }) => {
  const email = payload.email.trim().toLowerCase();

  const otpKey = getRegistrationOTPKey(email);
  const dataKey = getRegistrationDataKey(email);

  // Get OTP and registration data from Redis
  const savedOTP = await redisClient.get(otpKey);
  const savedData = await redisClient.get(dataKey);

  if (!savedOTP || !savedData) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      "OTP expired or registration data not found. Please register again",
    );
  }

  if (savedOTP !== payload.otp) {
    throw new AppError(httpStatus.BAD_REQUEST, "Invalid OTP");
  }

  const registrationData = JSON.parse(savedData) as IRegister;

  // Check user again to prevent duplicate creation
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

  // Create verified user
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

  // Remove temporary registration data
  await redisClient.del([otpKey, dataKey]);

  // Send welcome email
  try {
    const html = await ejs.renderFile(
      path.join(process.cwd(), "src/app/templates/student-welcome-email.ejs"),
      {
        name: user.name,
      },
    );

    await transporter.sendMail({
      from: config.email_sender,
      to: user.email,
      subject: "Welcome to Notwise",
      html,
    });
  } catch (error) {
    // Account is already created, so don't fail verification
    console.error("Welcome email error:", error);
  }

  // Generate access and refresh tokens
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

  const { password, ...userWithoutPassword } = user;

  return {
    user: userWithoutPassword,
    accessToken,
    refreshToken,
  };
};

// 3. Resend Registration OTP
const resendRegistrationOTP = async (email: string) => {
  email = email.trim().toLowerCase();

  const dataKey = getRegistrationDataKey(email);
  const otpKey = getRegistrationOTPKey(email);

  const savedData = await redisClient.get(dataKey);

  if (!savedData) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      "Registration session expired. Please register again",
    );
  }

  const registrationData = JSON.parse(savedData) as IRegister;

  const otp = randomInt(100000, 1000000).toString();

  await redisClient.set(otpKey, otp, { EX: 300 });

  try {
    const html = await ejs.renderFile(
      path.join(process.cwd(), "src/app/templates/registration-user-otp.ejs"),
      {
        name: registrationData.name,
        otp,
      },
    );

    await transporter.sendMail({
      from: config.email_sender,
      to: email,
      subject: "Notwise email verification",
      html,
    });
  } catch (error) {
    await redisClient.del(otpKey);
    throw new AppError(
      httpStatus.INTERNAL_SERVER_ERROR,
      "Failed to send OTP email",
    );
  }

  return { email, message: "A new OTP has been sent" };
};

// 4. Login
const login = async (payload: { email: string; password: string }) => {
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
    throw new AppError(
      httpStatus.BAD_REQUEST,
      "This account does not have a password",
    );
  }

  const isPasswordMatched = await bcrypt.compare(
    payload.password,
    user.password,
  );

  if (!isPasswordMatched) {
    throw new AppError(httpStatus.UNAUTHORIZED, "Invalid email or password");
  }

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

  const { password, ...userWithoutPassword } = user;

  return {
    user: userWithoutPassword,
    accessToken,
    refreshToken,
  };
};

// 5. Get My Profile
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
    },
  });

  if (!user || user.status === "BLOCKED") {
    throw new AppError(httpStatus.UNAUTHORIZED, "Please login again");
  }

  return user;
};

// 6. Refresh Access Token
const refreshToken = async (token: string) => {
  const verified = jwtUtils.verifyToken(token, config.refresh_secret);

  if (!verified.success) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      "Invalid or expired refresh token",
    );
  }

  const { userId } = verified.data as {
    userId: string;
  };

  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user || user.deletedAt) {
    throw new AppError(httpStatus.UNAUTHORIZED, "Please login again");
  }

  if (user.status === "BLOCKED") {
    throw new AppError(httpStatus.FORBIDDEN, "Your account has been blocked");
  }

  const accessToken = jwtUtils.createToken(
    {
      userId: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
    config.access_secret,
    config.access_expires_in as string,
  );

  return { accessToken };
};

// Forgot password Redis key
const getForgotPasswordOTPKey = (email: string) =>
  `notwise:forgot-password:otp:${email}`;

// 7. Forgot Password
const forgotPassword = async (email: string) => {
  email = email.trim().toLowerCase();

  const user = await prisma.user.findUnique({
    where: { email },
  });

  // Generic response prevents revealing whether an email exists
  if (!user || user.deletedAt || !user.password) {
    return {
      email,
      message: "If the account exists, a reset OTP will be sent",
    };
  }

  const otp = randomInt(100000, 1000000).toString();

  await redisClient.set(getForgotPasswordOTPKey(email), otp, { EX: 300 });

  try {
    const html = await ejs.renderFile(
      path.join(process.cwd(), "src/app/templates/forget-password-otp.ejs"),
      {
        name: user.name,
        otp,
      },
    );

    await transporter.sendMail({
      from: config.email_sender,
      to: email,
      subject: "Notwise password reset OTP",
      html,
    });
  } catch (error) {
    await redisClient.del(getForgotPasswordOTPKey(email));

    throw new AppError(
      httpStatus.INTERNAL_SERVER_ERROR,
      "Failed to send password reset OTP",
    );
  }

  return {
    email,
    message: "Password reset OTP has been sent",
  };
};

// 8. Resend Forgot Password OTP
const resendForgotPasswordOTP = async (email: string) => {
  return forgotPassword(email);
};

// 9. Reset Password
const resetPassword = async (payload: {
  email: string;
  otp: string;
  newPassword: string;
}) => {
  const email = payload.email.trim().toLowerCase();
  const otpKey = getForgotPasswordOTPKey(email);

  const savedOTP = await redisClient.get(otpKey);

  if (!savedOTP) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      "OTP expired. Please request a new OTP",
    );
  }

  if (savedOTP !== payload.otp) {
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
      to: email,
      subject: "Notwise password changed",
      html,
    });
  } catch (error) {
    console.error("Password change email error:", error);
  }

  return {
    message: "Password reset successfully",
  };
};

export const AuthService = {
  register,
  verifyEmail,
  resendRegistrationOTP,
  login,
  getMe,
  refreshToken,
  forgotPassword,
  resendForgotPasswordOTP,
  resetPassword,
};