import express, { Application, Request, Response } from "express";
import httpStatus from "http-status";
const app: Application = express();

app.use("/", async (req: Request, res: Response) => {
  res.status(httpStatus.OK).json({
    success: true,
    message: "Welcome to our Note Wise Project",
  });
});

export default app;
