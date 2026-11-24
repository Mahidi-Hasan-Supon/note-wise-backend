
import { Router } from "express";

import { AuthValidation } from "./auth.validation";
import { validationRequest } from "../../middleware/validationRequestByZod";
import { auth } from "../../middleware/checkAuth";
import { authController } from "./auth.controller";


const router = Router();

router.post(
  "/register",
  validationRequest(AuthValidation.register),
  authController.registerUser,
);

router.post(
  "/verify-email",
  validationRequest(AuthValidation.verifyEmail),
  authController.verifyEmail,
);

router.post(
  "/resend-registration-otp",
  validationRequest(AuthValidation.resendOTP),
  authController.resendVerificationOtp,
);

router.post(
  "/login",
  validationRequest(AuthValidation.login),
  authController.loginUser,
);

router.get(
  "/me",
  auth(),
  authController.getMe,
);

router.post(
  "/refresh-token",
  authController.refreshToken,
);

router.post(
  "/forgot-password",
  validationRequest(AuthValidation.forgotPassword),
  authController.forgotPassword,
);

router.post(
  "/resend-forgot-password-otp",
  validationRequest(AuthValidation.resendOTP),
  authController.resendForgotPasswordOtp,
);

router.post(
  "/reset-password",
  validationRequest(AuthValidation.resetPassword),
  authController.resetPassword,
);

router.post(
  "/logout",
  authController.logOut,
);

export const AuthRoutes = router;


