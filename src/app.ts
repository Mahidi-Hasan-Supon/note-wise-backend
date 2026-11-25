import cookieParser from "cookie-parser";
import express, { Application, Request, Response } from "express";
import httpStatus from "http-status";
import cors from "cors";
import config from "./app/config";
import { AuthRoutes } from "./app/modules/auth/auth.route";
import { notFound } from "./app/middleware/notFound";
import { globalErrorHandler } from "./app/middleware/globalError";

const app: Application = express();

app.use(
  cors({
    origin: config.client_url,
    credentials: true,
  }),
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());




app.use("/api/v3/auth", AuthRoutes);

app.get("/", (req: Request, res: Response) => {
  res.status(httpStatus.OK).json({
    success: true,
    message: "Welcome to our Note Wise Project",
  });
});


app.use(notFound);
app.use(globalErrorHandler);


export default app;
