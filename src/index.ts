import "dotenv-flow/config";

import { serve } from "@hono/node-server";
import { swaggerUI } from "@hono/swagger-ui";
import { OpenAPIHono } from "@hono/zod-openapi";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { healthRouter } from "./routes/health";
import { mineskinRouter } from "./routes/mineskin";

const PORT = process.env.SERVER_PORT
  ? parseInt(process.env.SERVER_PORT, 10)
  : 3000;

const app = new OpenAPIHono();

app.use("*", logger());

app.use(
  "*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["*"],
    credentials: true,
  }),
);

app.get(
  "/swagger",
  swaggerUI({
    url: "/openapi",
  }),
);

app.doc("/openapi", {
  openapi: "3.0.0",
  info: {
    title: "Axolotl",
    version: "1.0.0",
    description: "A lightweight health-check API",
  },
  tags: [
    { name: "health", description: "Health check endpoint" },
    {
      name: "mineskin",
      description:
        "MineSkin proxy endpoints that inject the configured API key.",
    },
  ],
  servers: [
    { url: `https://axolotl.skinsrestorer.net`, description: "Main Server" },
    { url: `http://localhost:${PORT}`, description: "Local Server" },
  ],
});

app.get("/", (c) => {
  return c.redirect("/swagger");
});

app.route("/health", healthRouter);
app.route("/mineskin", mineskinRouter);

app.notFound((c) => {
  return c.json({ error: "Not Found" }, 404);
});

app.onError((err, c) => {
  console.error("Error:", err);
  return c.json({ error: "Internal Server Error" }, 500);
});

serve(
  {
    fetch: app.fetch,
    port: PORT,
  },
  (info) => {
    console.log(`🦎 Server started at http://localhost:${info.port}`);
    console.log(
      `📚 API Documentation available at http://localhost:${info.port}/swagger`,
    );
  },
);
