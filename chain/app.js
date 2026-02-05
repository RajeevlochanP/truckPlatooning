import { initialize } from "zokrates-js";
import * as bls from "@noble/bls12-381";
import express from "express";
import multer from "multer";
import morgan from "morgan";
import bigInt from 'big-integer';
import crypto from 'crypto';

const app = express();
const port = 3000;

const upload = multer({ storage: multer.memoryStorage() });

app.use(express.json());
app.use(morgan("dev"));

let zokratesProvider; 


let globalVerifierKey = null;
let verifierKeySetAt = null;

const userStore = new Map();

function randBetween(min, max) {
    const range = max.minus(min);
    const byteLength = Math.ceil(range.bitLength() / 8);
    let randomNum;
    do {
        const buffer = crypto.randomBytes(byteLength);
        const hex = buffer.toString('hex');
        randomNum = bigInt(hex, 16);
    } while (randomNum.geq(range));
    return randomNum.add(min);
}

/**
 * UTILITY: Fiat-Shamir Challenge Generator
 * Hashes inputs (N, g, C, A) to create a non-interactive challenge 'e'
 */
function generateChallenge(N, g, C, A) {
    const hash = crypto.createHash('sha256');
    // Concatenate standard string representations of the big integers
    hash.update(N.toString());
    hash.update(g.toString());
    hash.update(C.toString());
    hash.update(A.toString());
    
    // Convert hex hash to BigInt
    const hex = hash.digest('hex');
    return bigInt(hex, 16);
}

/* VERIFIER FUNCTION */
function verifierCheckProof(pubKey, C, proof) {
    const { n, g, n2 } = pubKey;
    
    // Convert proof strings back to BigInts
    const A = bigInt(proof.A);
    const e = bigInt(proof.e);
    const z1 = bigInt(proof.z1);
    const z2 = bigInt(proof.z2);
    const Cipher = bigInt(C);

    // 1. Verify Challenge Integrity
    const e_check = generateChallenge(n, g, Cipher, A);
    
    if (e.neq(e_check)) {
        console.error("FAIL: Hash challenge mismatch.");
        return false;
    }

    // 2. Verify Mathematical Equality
    // LHS = g^z1 * z2^n mod n^2
    const g_z1 = g.modPow(z1, n2);
    const z2_n = z2.modPow(n, n2);
    const LHS = g_z1.multiply(z2_n).mod(n2);

    // RHS = A * C^e mod n^2
    const C_e = Cipher.modPow(e, n2);
    const RHS = A.multiply(C_e).mod(n2);

    // Compare
    const isValid = LHS.eq(RHS);

    if (isValid) {
        console.log("SUCCESS: ZKP Validated. Truck knows the path.");
    } else {
        console.error("FAIL: Mathematical verification failed.");
    }

    return isValid;
}

function generateUserId() {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `0x${timestamp}${random}`.toUpperCase();
}

async function initZokrates() {
  zokratesProvider = await initialize();
  console.log("ZoKrates provider initialized");
}

// Helper function to aggregate BLS public keys
function aggregatePKs(pks) {
  return bls.aggregatePublicKeys(pks);
}

// Helper function to verify BLS proof
async function verifyBLSProof(omega, h, pk) {
  return await bls.verify(omega, h, pk);
}

// Helper to parse uploaded JSON file from buffer
function parseFileBuffer(file) {
  return JSON.parse(file.buffer.toString("utf8"));
}

app.get("/", (req, res) => {
  res.json({
    status: "ok",
    message: "Truck Platooning Verifiable Computation Chain",
    verifierKeySet: !!globalVerifierKey,
    registeredUsers: userStore.size,
    endpoints: {
      "/verifier-key": "POST (once) - Set global verifier key | GET - View status",
      "/register": "POST - Register user: { authPks, id? } → returns id",
      "/users": "GET - List all registered users",
      "/users/:id": "GET/DELETE - Get or unregister user",
      "/verify/path": "POST - proof, output files",
      "/verify/auth": "POST - authProof file + id",
      "/verify/all": "POST - all proofs + id",
    },
  });
});

app.post("/verifier-key", (req, res) => {
  try {
    const { verifierKey } = req.body;

    if (!verifierKey) {
      return res.status(400).json({
        success: false,
        error: "verifierKey is required",
      });
    }

    if (globalVerifierKey !== null) {
      return res.status(403).json({
        success: false,
        error: "Verifier key already set and cannot be modified",
        setAt: verifierKeySetAt,
      });
    }

    globalVerifierKey = verifierKey;
    verifierKeySetAt = new Date().toISOString();

    console.log(`Global verifier key set at ${verifierKeySetAt}`);

    res.status(201).json({
      success: true,
      message: "Verifier key set successfully (immutable)",
      setAt: verifierKeySetAt,
    });
  } catch (error) {
    console.error("Verifier key error:", error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

app.get("/verifier-key", (req, res) => {
  res.json({
    success: true,
    isSet: !!globalVerifierKey,
    setAt: verifierKeySetAt,
  });
});

app.post("/register", (req, res) => {
  try {
    let { authPks } = req.body;
    // Coerce id to string (handles both "1" and 1)
    let id = req.body.id?.toString();

    if (!authPks) {
      return res.status(400).json({
        success: false,
        error: "authPks is required for registration",
      });
    }

    if (!Array.isArray(authPks) || !authPks.every(Array.isArray)) {
      return res.status(400).json({
        success: false,
        error: "authPks must be an array of arrays (k serialized public keys)",
      });
    }

    if (!id) {
      id = generateUserId();
    } else if (userStore.has(id)) {
      return res.status(409).json({
        success: false,
        error: `ID '${id}' already exists. Use a different ID or omit to auto-generate.`,
      });
    }

    userStore.set(id, {
      authPks,
      numKeys: authPks.length,
      registeredAt: new Date().toISOString(),
    });

    console.log(`User registered: ${id} (${authPks.length} keys)`);

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      id,
      numKeys: authPks.length,
      registeredAt: userStore.get(id).registeredAt,
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

app.get("/users", (req, res) => {
  const users = Array.from(userStore.entries()).map(([id, data]) => ({
    id,
    numKeys: data.numKeys,
    registeredAt: data.registeredAt,
  }));

  res.json({
    success: true,
    totalUsers: userStore.size,
    users,
  });
});

app.get("/users/:id", (req, res) => {
  const { id } = req.params;

  if (!userStore.has(id)) {
    return res.status(404).json({
      success: false,
      error: `User '${id}' not found`,
    });
  }

  const user = userStore.get(id);
  res.json({
    success: true,
    id,
    numKeys: user.numKeys,
    registeredAt: user.registeredAt,
  });
});

app.delete("/users/:id", (req, res) => {
  const { id } = req.params;

  if (!userStore.has(id)) {
    return res.status(404).json({
      success: false,
      error: `User '${id}' not found`,
    });
  }

  userStore.delete(id);
  console.log(`🗑️ User unregistered: ${id}`);

  res.json({
    success: true,
    message: `User '${id}' unregistered successfully`,
  });
});

app.post("/verify/path",
  upload.fields([
    { name: "proof", maxCount: 1 },
    { name: "output", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const files = req.files;

      // Accept either JSON body or file uploads
      let proof, output;

      if (files?.proof && files?.output) {
        // File upload mode
        proof = parseFileBuffer(files.proof[0]);
        output = parseFileBuffer(files.output[0]);
      } else if (req.body.proof && req.body.output) {
        // JSON body mode
        proof = req.body.proof;
        output = req.body.output;
      } else {
        return res.status(400).json({
          success: false,
          error: "Missing required: proof and output (as files or JSON body)",
        });
      }

      if (!globalVerifierKey) {
        return res.status(400).json({
          success: false,
          error: "Global verifier key not set. Set it first via POST /verifier-key",
        });
      }

      const isVerified = zokratesProvider.verify(globalVerifierKey, proof, output);

      res.json({
        success: true,
        verified: isVerified,
        message: `Path verification ${isVerified ? "successful" : "failed"}`,
      });
    } catch (error) {
      console.error("Path verification error:", error);
      res.status(500).json({
        success: false,
        verified: false,
        error: error.message,
      });
    }
  }
);

app.post("/verify/auth",
  upload.fields([
    { name: "authProof", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const files = req.files;
      // Coerce id to string (handles both "1" and 1)
      const id = req.body.id?.toString();

      // Accept either JSON body or file upload for authProof
      let authProof;

      if (files?.authProof) {
        // File upload mode
        authProof = parseFileBuffer(files.authProof[0]);
      } else if (req.body.omegaAgg && req.body.h) {
        // JSON body mode (direct fields)
        authProof = {
          omegaAgg: req.body.omegaAgg,
          h: req.body.h,
        };
      } else {
        return res.status(400).json({
          success: false,
          error: "Missing required: authProof file or { omegaAgg, h } in JSON body",
        });
      }

      if (!id) {
        return res.status(400).json({
          success: false,
          error: "Missing required field: id (user's registered ID)",
        });
      }

      if (!userStore.has(id)) {
        return res.status(404).json({
          success: false,
          error: `User '${id}' not found. Register first via POST /register`,
        });
      }

      const authPks = userStore.get(id).authPks;

      const omegaAgg = Uint8Array.from(authProof.omegaAgg);
      const hash = Uint8Array.from(authProof.h);
      const pksAsUint8Arrays = authPks.map((bytes) => Uint8Array.from(bytes));
      const pkAgg = aggregatePKs(pksAsUint8Arrays);

      const isVerified = await verifyBLSProof(omegaAgg, hash, pkAgg);

      res.json({
        success: true,
        verified: isVerified,
        id,
        message: `Auth verification ${isVerified ? "successful" : "failed"}`,
      });
    } catch (error) {
      console.error("Auth verification error:", error);
      res.status(500).json({
        success: false,
        verified: false,
        error: error.message,
      });
    }
  }
);

app.post(
  "/verify/all",
  upload.fields([
    { name: "proof", maxCount: 1 },
    { name: "output", maxCount: 1 },
    { name: "authProof", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const files = req.files;
      // Coerce id to string
      const id = req.body.id?.toString();

      // Accept either JSON body or file uploads
      let proof, output, authProof;

      if (files?.proof && files?.output) {
        proof = parseFileBuffer(files.proof[0]);
        output = parseFileBuffer(files.output[0]);
      } else if (req.body.proof && req.body.output) {
        proof = req.body.proof;
        output = req.body.output;
      } else {
        return res.status(400).json({
          success: false,
          error: "Missing required: proof and output (as files or JSON body)",
        });
      }

      if (files?.authProof) {
        authProof = parseFileBuffer(files.authProof[0]);
      } else if (req.body.omegaAgg && req.body.h) {
        authProof = { omegaAgg: req.body.omegaAgg, h: req.body.h };
      } else {
        return res.status(400).json({
          success: false,
          error: "Missing required: authProof file or { omegaAgg, h } in JSON body",
        });
      }

      if (!globalVerifierKey) {
        return res.status(400).json({
          success: false,
          error: "Global verifier key not set. Set it first via POST /verifier-key",
        });
      }

      if (!id) {
        return res.status(400).json({
          success: false,
          error: "Missing required field: id (user's registered ID)",
        });
      }

      if (!userStore.has(id)) {
        return res.status(404).json({
          success: false,
          error: `User '${id}' not found. Register first via POST /register`,
        });
      }

      const authPks = userStore.get(id).authPks;

      // Verify path proof using global verifier key
      const isPathVerified = zokratesProvider.verify(globalVerifierKey, proof, output);

      // Verify auth proof
      const omegaAgg = Uint8Array.from(authProof.omegaAgg);
      const hash = Uint8Array.from(authProof.h);
      const pksAsUint8Arrays = authPks.map((bytes) => Uint8Array.from(bytes));
      const pkAgg = aggregatePKs(pksAsUint8Arrays);
      const isAuthVerified = await verifyBLSProof(omegaAgg, hash, pkAgg);

      const allVerified = isPathVerified && isAuthVerified;

      res.json({
        success: true,
        verified: allVerified,
        pathVerified: isPathVerified,
        authVerified: isAuthVerified,
        id,
        message: allVerified
          ? "All verifications successful"
          : `Verification failed - Path: ${isPathVerified}, Auth: ${isAuthVerified}`,
      });
    } catch (error) {
      console.error("Verification error:", error);
      res.status(500).json({
        success: false,
        verified: false,
        error: error.message,
      });
    }
  }
);

initZokrates()
  .then(() => {
    app.listen(port, () => {
      console.log(`\n Verifiable Computation Chain running on http://localhost:${port}\n`);
      console.log("Endpoints:");
      console.log("  GET  /              - Health check & info");
      console.log("  POST /verifier-key  - Set global verifier key (once, immutable)");
      console.log("  GET  /verifier-key  - Check verifier key status");
      console.log("  POST /register      - Register user: { authPks, id? }");
      console.log("  GET  /users         - List all registered users");
      console.log("  GET  /users/:id     - Get user status");
      console.log("  DELETE /users/:id   - Unregister a user");
      console.log("  POST /verify/path   - Verify path: proof, output");
      console.log("  POST /verify/auth   - Verify auth: authProof + id");
      console.log("  POST /verify/all    - Verify all: proofs + id\n");
    });
  })
  .catch((err) => {
    console.error("Failed to initialize ZoKrates:", err);
    process.exit(1);
  });