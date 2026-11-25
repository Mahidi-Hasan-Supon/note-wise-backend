import app from "./app";
import config from "./app/config/index";
import { prisma } from "./app/lib/prisms";
import { redisClient } from "./app/lib/redis";

const port = config.port;

async function main() {
  try {
    await prisma.$connect();

    await redisClient.connect()
    console.log("Redis server connected successfully");


    console.log("Database connected successfully");
    app.listen(port, () => {
      console.log(`Example app listening on port ${port}`);
    });
  } catch (error) {
    console.log("Error starting the server", error);
    await prisma.$disconnect();
    process.exit(1);
  }
}
main();
