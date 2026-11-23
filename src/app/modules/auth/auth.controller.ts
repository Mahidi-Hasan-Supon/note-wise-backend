import type { Request, Response } from "express";
import httpStatus from "http-status";
import { AuthService } from "./auth.service";
import { sendResponse } from "../../utiles/sendResponse";


const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax" as const,
  path: "/",
};

// Helper: set authentication cookies
const setAuthCookies = (
  res: Response,
  accessToken: string,
  refreshToken: string,
) => {
  res.cookie("accessToken", accessToken, cookieOptions);
  res.cookie("refreshToken", refreshToken, cookieOptions);
};

// Register
const register = async (req: Request, res: Response) => {
  const result = await AuthService.register(req.body);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.CREATED,
    message: "Registration successful. Please verify your email",
    data: result,
  });
};

// Verify Email
const verifyEmail = async (req: Request, res: Response) => {
  const result = await AuthService.verifyEmail(req.body);

  setAuthCookies(res, result.accessToken, result.refreshToken);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: "Email verified successfully",
    data: { user: result.user },
  });
};

// Resend Registration OTP
const resendRegistrationOTP = async (req: Request, res: Response) => {
  const result = await AuthService.resendRegistrationOTP(req.body.email);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: result.message,
    data: result,
  });
};

// Login
const login = async (req: Request, res: Response) => {
  const result = await AuthService.login(req.body);

  setAuthCookies(res, result.accessToken, result.refreshToken);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: "Login successful",
    data: { user: result.user },
  });
};

// Get Me
const getMe = async (req: Request, res: Response) => {
    const userId = req.user?.userId
  const result = await AuthService.getMe(userId as string);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: "Profile retrieved successfully",
    data: result,
  });
};

// Refresh Token
const refreshToken = async (req: Request, res: Response) => {
  const token = req.cookies?.refreshToken || req.body.refreshToken;

  if (!token) {
    return sendResponse(res, {
      success: false,
      statusCode: httpStatus.UNAUTHORIZED,
      message: "Refresh token is required",
      data: null,
    });
  }

  const result = await AuthService.refreshToken(token);

  res.cookie("accessToken", result.accessToken, cookieOptions);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: "Access token refreshed successfully",
    data: null,
  });
};

// Forgot Password
const forgotPassword = async (req: Request, res: Response) => {
    const email =req.body.email
  const result = await AuthService.forgotPassword(email);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: result.message,
    data: result,
  });
};

// Resend Forgot Password OTP
const resendForgotPasswordOTP = async (req: Request, res: Response) => {
    const email =req.body.email
  const result = await AuthService.resendForgotPasswordOTP(email);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: result.message,
    data: result,
  });
};

// Reset Password
const resetPassword = async (req: Request, res: Response) => {
  const result = await AuthService.resetPassword(req.body);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: result.message,
    data: result,
  });
};

// Logout
const logout = async (_req: Request, res: Response) => {
  res.clearCookie("accessToken", cookieOptions);
  res.clearCookie("refreshToken", cookieOptions);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: "Logout successful",
    data: null,
  });
};

export const AuthController = {
  register,
  verifyEmail,
  resendRegistrationOTP,
  login,
  getMe,
  refreshToken,
  forgotPassword,
  resendForgotPasswordOTP,
  resetPassword,
  logout,
};
