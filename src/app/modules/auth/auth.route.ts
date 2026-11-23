
import { Router } from "express";

import { AuthController } from "./auth.controller";
import { AuthValidation } from "./auth.validation";
import { validationRequest } from "../../middleware/validationRequestByZod";
import { auth } from "../../middleware/checkAuth";


const router = Router();

router.post(
  "/register",
  validationRequest(AuthValidation.register),
  AuthController.register,
);

router.post(
  "/verify-email",
  validationRequest(AuthValidation.verifyEmail),
  AuthController.verifyEmail,
);

router.post(
  "/resend-registration-otp",
  validationRequest(AuthValidation.resendOTP),
  AuthController.resendRegistrationOTP,
);

router.post(
  "/login",
  validationRequest(AuthValidation.login),
  AuthController.login,
);

router.get(
  "/me",
  auth(),
  AuthController.getMe,
);

router.post(
  "/refresh-token",
  AuthController.refreshToken,
);

router.post(
  "/forgot-password",
  validationRequest(AuthValidation.forgotPassword),
  AuthController.forgotPassword,
);

router.post(
  "/resend-forgot-password-otp",
  validationRequest(AuthValidation.resendOTP),
  AuthController.resendForgotPasswordOTP,
);

router.post(
  "/reset-password",
  validationRequest(AuthValidation.resetPassword),
  AuthController.resetPassword,
);

router.post(
  "/logout",
  AuthController.logout,
);

export const AuthRoutes = router;


