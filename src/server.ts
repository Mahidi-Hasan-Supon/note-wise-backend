import app from "./app.js";
import config from "./app/config/index.js";
import { prisma } from "./app/lib/prisms.js";

const port = config.port;

async function main() {
  try {
    await prisma.$connect();
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
