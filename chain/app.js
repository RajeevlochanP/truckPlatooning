/**
 * Truck Platooning Verifiable Computation Chain
 * Main Application Entry Point
 */
import express from "express";
import morgan from "morgan";

import config from "./config/index.js";
import { userRoutes, verifyRoutes } from "./routes/index.js";
import { getUserCount } from "./store/user.store.js";
import * as paillierBigint from "paillier-bigint";

const app = express();

// Middleware
app.use(express.json());
app.use(morgan("dev"));

// Health check / root endpoint
app.get("/", (req, res) => {
  res.json({
    status: "ok",
    message: config.appName,
    verifierKeySet: isVerifierKeySet(),
    registeredUsers: getUserCount(),
    endpoints: {
      "/verifier-key": "POST (once) - Set global verifier key | GET - Status",
      "/register": "POST - Register user: { authPks, pubKey, id? }",
      "/users": "GET - List all registered users",
      "/users/:id": "GET/DELETE - Get or unregister user",
      "/verify/path": "POST - Verify encrypted path proofs",
      "/verify/auth": "POST - Verify BLS auth proof",
    },
  });
});

// Mount routes
app.use("/verify", verifyRoutes); // /verify/path, /verify/auth
app.use(userRoutes);          // /register, /users, /users/:id

// Initialize ZoKrates and start server
async function start() {
  try {
    app.listen(config.port, () => {
      console.log(`\n${config.appName}`);
      console.log(`Running on http://localhost:${config.port}\n`);
      console.log("Endpoints:");
      console.log("  GET  /              - Health check & info");
      console.log("  POST /register      - Register user: { authPks, pubKey, id? }");
      console.log("  GET  /users         - List all registered users");
      console.log("  GET  /users/:id     - Get user details");
      console.log("  DELETE /users/:id   - Unregister a user");
      console.log("  POST /verify/path   - Verify encrypted path proofs");
      console.log("  POST /verify/auth   - Verify BLS auth proof\n");
    });
  } catch (err) {
    console.error("Failed to initialize:", err);
    process.exit(1);
  }
}

start();
