import type { Request, Response } from "express";
import httpStatus from "http-status";

import { authService } from "./auth.service";
import { sendResponse } from "../../utiles/sendResponse";
import { catchAsync } from "../../utiles/catchAsync";
import { AppError } from "../../utiles/appError";
import config from "../../config";

// Register User
const registerUser = catchAsync(async (req: Request, res: Response) => {
  await authService.registerUser(req.body);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.CREATED,
    message: "OTP sent to your email. Please check it and verify your email",
    data: null,
  });
});

// Login User
const loginUser = catchAsync(async (req: Request, res: Response) => {
  const result = await authService.loginUser(req.body);

  const { accessToken, refreshToken, user } = result;

  // res.cookie("accessToken", accessToken, {
  //   httpOnly: true,
  //   secure: config.node_env === "development" ? false : true,
  //   sameSite: config.node_env === "development" ? "lax" : "none",
  //   maxAge: 1000 * 60 * 60 * 24, // 1 day
  // });

  // res.cookie("refreshToken", refreshToken, {
  //   httpOnly: true,
  //   secure: config.node_env === "development" ? false : true,
  //   sameSite: config.node_env === "development" ? "lax" : "none",
  //   maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
  // });

   res.cookie("accessToken", accessToken, {
        httpOnly : true,
        secure : false,
        sameSite : "none",
        maxAge : 1000 * 60 * 60 * 24 // 24 hour or 1 day
    })

    res.cookie("refreshToken", refreshToken, {
        httpOnly : true,
        secure : false,
        sameSite : "none",
        maxAge : 1000 * 60 * 60 * 24 * 7 // 7 day
    })

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: "Login successful",
    data: {
      user,
      accessToken,
      refreshToken,
    },
  });
});

//logout
const logOut = catchAsync(async (_req: Request, res: Response) => {
  const cookieOptions = {
    httpOnly: true,
    secure: config.node_env === "development" ? false : true,
    sameSite: config.node_env === "development" ? "lax" as const : "none" as const,
  };

  res.clearCookie("accessToken", cookieOptions);
  res.clearCookie("refreshToken", cookieOptions);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: "User logout successfully",
    data: null,
  });
});

// Get Me
const getMe = catchAsync(async (req: Request, res: Response) => {
  const userId = req.user?.userId;

  if (!userId) {
    throw new AppError(httpStatus.UNAUTHORIZED, "Please login again");
  }

  const user = await authService.getMe(userId);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: "User retrieved successfully",
    data: user,
  });
});

// Verify Email
const verifyEmail = catchAsync(async (req: Request, res: Response) => {
  const payload = req.body;

  const result = await authService.verifyEmail(payload);

  const { accessToken, refreshToken, user } = result;

  // res.cookie("accessToken", accessToken, {
  //   httpOnly: true,
  //   secure: config.node_env === "development" ? false : true,
  //   sameSite: config.node_env === "development" ? "lax" : "none",
  //   maxAge: 1000 * 60 * 60 * 24, // 1 day
  // });

  // res.cookie("refreshToken", refreshToken, {
  //   httpOnly: true,
  //   secure: config.node_env === "development" ? false : true,
  //   sameSite: config.node_env === "development" ? "lax" : "none",
  //   maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
  // });

   res.cookie("accessToken", accessToken, {
        httpOnly : true,
        secure : false,
        sameSite : "none",
        maxAge : 1000 * 60 * 60 * 24 // 24 hour or 1 day
    })

    res.cookie("refreshToken", refreshToken, {
        httpOnly : true,
        secure : false,
        sameSite : "none",
        maxAge : 1000 * 60 * 60 * 24 * 7 // 7 day
    })

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: "Email verified successfully",
    data: {
      user,
      accessToken,
      refreshToken,
    },
  });
});

// Resend Verification OTP
const resendVerificationOtp = catchAsync(
  async (req: Request, res: Response) => {
    const { email } = req.body;

    await authService.resendVerificationOtp(email);

    sendResponse(res, {
      success: true,
      statusCode: httpStatus.OK,
      message: "Verification OTP resent successfully",
      data: null,
    });
  },
);

// Refresh Token
const refreshToken = catchAsync(async (req: Request, res: Response) => {
  const token = req.cookies?.refreshToken;

  if (!token) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      "Refresh token is missing",
    );
  }

  const result = await authService.refreshToken(token);

  const { accessToken, refreshToken: newRefreshToken } = result;

  // res.cookie("accessToken", accessToken, {
  //   httpOnly: true,
  //   secure: config.node_env === "development" ? false : true,
  //   sameSite: config.node_env === "development" ? "lax" : "none",
  //   maxAge: 1000 * 60 * 60 * 24, // 1 day
  // });

  // res.cookie("refreshToken", newRefreshToken, {
  //   httpOnly: true,
  //   secure: config.node_env === "development" ? false : true,
  //   sameSite: config.node_env === "development" ? "lax" : "none",
  //   maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
  // });

   res.cookie("accessToken", accessToken, {
        httpOnly : true,
        secure : false,
        sameSite : "none",
        maxAge : 1000 * 60 * 60 * 24 // 24 hour or 1 day
    })

    res.cookie("refreshToken", refreshToken, {
        httpOnly : true,
        secure : false,
        sameSite : "none",
        maxAge : 1000 * 60 * 60 * 24 * 7 // 7 day
    })

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: "Refresh token successful",
    data: {
      accessToken,
      refreshToken: newRefreshToken,
    },
  });
});

// Forgot Password
const forgotPassword = catchAsync(async (req: Request, res: Response) => {
  const result = await authService.forgotPassword(req.body.email);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: result.message,
    data: null,
  });
});

// Resend Forgot Password OTP
const resendForgotPasswordOtp = catchAsync(
  async (req: Request, res: Response) => {
    const result = await authService.resendForgotPasswordOtp(req.body.email);

    sendResponse(res, {
      success: true,
      statusCode: httpStatus.OK,
      message: result.message,
      data: null,
    });
  },
);

// Reset Password
const resetPassword = catchAsync(async (req: Request, res: Response) => {
  const result = await authService.resetPassword(req.body);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: result.message,
    data: null,
  });
});

export const authController = {
  registerUser,
  verifyEmail,
  resendVerificationOtp,
  loginUser,
  getMe,
  refreshToken,
  forgotPassword,
  resendForgotPasswordOtp,
  resetPassword,
  logOut,
};
