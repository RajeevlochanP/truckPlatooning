import { Router } from 'express';
import { verifyAuthProof,verifyPathProofs } from '../helpers/index.js';
import { getUser, hasUser, storeUserPath } from '../store/index.js';

const router = Router();

router.post('/path', async (req, res) => {
  try {
    const id = req.body.id?.toString();
    const { encryptedPath, proofs } = req.body;

    // Validation
    if (!id) {
      return res.status(400).json({
        success: false,
        error: "Missing required field: id",
      });
    }

    if (!hasUser(id)) {
      return res.status(404).json({
        success: false,
        error: `User '${id}' not found. Register first via POST /register`,
      });
    }

    if (!encryptedPath || !Array.isArray(encryptedPath)) {
      return res.status(400).json({
        success: false,
        error: "Missing or invalid encryptedPath array",
      });
    }

    if (!proofs || !Array.isArray(proofs)) {
      return res.status(400).json({
        success: false,
        error: "Missing or invalid proofs array",
      });
    }

    if (encryptedPath.length !== proofs.length) {
      return res.status(400).json({
        success: false,
        error: "encryptedPath and proofs arrays must have same length",
      });
    }

    // Get user's pubKey
    const user = getUser(id);
    if (!user.pubKey) {
      return res.status(400).json({
        success: false,
        error: "User does not have a pubKey registered",
      });
    }

    // Verify all proofs
    const { allValid, results } = verifyPathProofs(user.pubKey, encryptedPath, proofs);

    // If all proofs valid, store the encrypted path
    if (allValid) {
      storeUserPath(id, encryptedPath);
    }

    res.json({
      success: true,
      verified: allValid,
      id,
      pathLength: encryptedPath.length,
      results,
      message: allValid
        ? "All path proofs verified successfully. Path stored."
        : "Some path proofs failed verification",
    });
  } catch (error) {
    console.error("Path verification error:", error);
    res.status(500).json({
      success: false,
      verified: false,
      error: error.message,
    });
  }
});


router.post('/auth', async (req, res) => {
    try {
      const id = req.body.id?.toString();
      const authProof = req.body.authProof;

      if (!authProof || !authProof.omegaAgg || !authProof.h) {
        return res.status(400).json({
          success: false,
          error: "Missing required: authProof object with { omegaAgg, h } in request body",
        });
      }

      if (!id) {
        return res.status(400).json({
          success: false,
          error: "Missing required field: id (user's registered ID)",
        });
      }

      if (!hasUser(id)) {
        return res.status(404).json({
          success: false,
          error: `User '${id}' not found. Register first via POST /register`,
        });
      }

      const user = getUser(id);
      const isVerified = await verifyAuthProof(authProof, user.authPks);

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

export default router;
