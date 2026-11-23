import cookieParser from "cookie-parser";
import express, { Application, Request, Response } from "express";
import httpStatus from "http-status";
import cors from 'cors';
import config from "./app/config/index.js";

const app: Application = express();


app.use(cors({
   origin: config.client_url,
    credentials: true 
  }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());



app.use("/", async (req: Request, res: Response) => {
  res.status(httpStatus.OK).json({
    success: true,
    message: "Welcome to our Note Wise Project",
  });
});

export default app;
