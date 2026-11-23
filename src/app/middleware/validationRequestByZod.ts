import { NextFunction, Request, Response } from "express";
import z from "zod";
import { catchAsync } from "../utiles/catchAsync.js";
import { AppError } from "../utiles/appError.js";
import httpStatus from 'http-status';

export const validationRequest = (zodSchema: z.ZodObject) => {
  return catchAsync((req: Request, res: Response, next: NextFunction) => {
    const body = req.body ?? {};
    const result = zodSchema.safeParse(body);

    // if (!result.success) {
    //   // console.log(result.error);
    //   // console.log(result.error.message);
    //   throw new Error(result.error.issues[0]?.message);
    // }
    if (!result.success) {
      throw new AppError(
        httpStatus.BAD_REQUEST,
        result.error.issues[0]?.message ?? "Validation error",
      );
    }

    req.body = result.data;

    next();
  });
};
