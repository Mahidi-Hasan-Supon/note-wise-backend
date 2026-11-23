import type { NextFunction, Request, Response } from "express";
import type { JwtPayload } from "jsonwebtoken";
import httpStatus from "http-status";
import { Role } from "../../../generated/prisma/enums.js";
import { catchAsync } from "../utiles/catchAsync.js";
import { AppError } from "../utiles/appError.js";
import { jwtUtils } from "../utiles/jwt.js";
import config from "../config/index.js";
import { prisma } from "../lib/prisms.js";

export interface RequestUser {
  name: string;
  email: string;
  role: Role;
  userId: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: RequestUser;
    }
  }
}

export const auth = (...requiredRole: Role[]) => {
  return catchAsync(
    async (req: Request, _res: Response, next: NextFunction) => {
      const token = req.cookies?.accessToken
        ? req.cookies.accessToken
        : req.headers.authorization?.startsWith("Bearer ")
          ? req.headers.authorization.split(" ")[1]
          : req.headers.authorization;

      if (!token) {
        throw new AppError(httpStatus.UNAUTHORIZED, "You are not logged in");
      }

      const verified = jwtUtils.verifyToken(token, config.access_secret);

      if (!verified.success) {
        throw new AppError(
          httpStatus.UNAUTHORIZED,
          "Invalid or expired token, please login again",
        );
      }

      const { userId } = verified.data as JwtPayload;

      // শুধু id দিয়ে খুঁজুন, বাকি তথ্য সবসময় database থেকে নিন
      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new AppError(httpStatus.UNAUTHORIZED, "Please login again");
      }

      if (!user || user.deletedAt) {
        throw new AppError(httpStatus.UNAUTHORIZED, "Please login again");
      }

      if (user.status === "BLOCKED") {
        throw new AppError(
          httpStatus.FORBIDDEN,
          "Your account has been blocked",
        );
      }
      // Role database থেকে যাচাই, token-এর পুরনো role দিয়ে না
      if (requiredRole.length && !requiredRole.includes(user.role)) {
        throw new AppError(
          httpStatus.FORBIDDEN,
          "Forbidden, you don't have permission",
        );
      }

      req.user = {
        userId: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      };

      next();
    },
  );
};
