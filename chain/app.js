import express from "express";
import morgan from "morgan";

import config from "./config/index.js";
import { userRoutes, verifyRoutes } from "./routes/index.js";
import { getUserCount } from "./store/user.store.js";
import * as paillierBigint from "paillier-bigint";

const app = express();

app.use(express.json());
app.use(morgan("dev"));

app.get("/", (req, res) => {
  res.json({
    status: "ok",
    message: config.appName,
    registeredUsers: getUserCount(),
    endpoints: {
      "POST /register":            "Register user: { authPks, pubKey, id? }",
      "GET  /users":               "List all registered users",
      "GET  /users/:id":           "Get user details",
      "GET  /users/:id/path":      "Get user's stored encrypted path",
      "DELETE /users/:id":         "Unregister a user",
      "POST /verify/path":         "Verify encrypted path proofs & store path",
      "POST /verify/auth":         "Verify BLS auth proof",
      "POST /verify/cBlindPath":   "Verify blind path proofs & store if matched",
    },
  });
});

app.use("/verify", verifyRoutes);
app.use(userRoutes);

async function start() {
  try {
    app.listen(config.port, () => {
      console.log(`\n${config.appName}`);
      console.log(`Running on http://localhost:${config.port}\n`);
      console.log("Endpoints:");
      console.log("  GET    /                    - Health check & info");
      console.log("  POST   /register            - Register user: { authPks, pubKey, id? }");
      console.log("  GET    /users               - List all registered users");
      console.log("  GET    /users/:id            - Get user details");
      console.log("  GET    /users/:id/path       - Get user's stored encrypted path");
      console.log("  DELETE /users/:id            - Unregister a user");
      console.log("  POST   /verify/path          - Verify encrypted path proofs & store path");
      console.log("  POST   /verify/auth          - Verify BLS auth proof");
      console.log("  POST   /verify/cBlindPath    - Verify blind path proofs & store if matched\n");
    });
  } catch (err) {
    console.error("Failed to initialize:", err);
    process.exit(1);
  }
}

start();
