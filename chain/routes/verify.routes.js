import { Router } from 'express';
import { verifyAuthProof, verifyPathProofs, verifyBlindMatch } from '../helpers/index.js';
import { getUser, hasUser, storeUserPath, storeUserBlindPath } from '../store/index.js';
import config from '../config/index.js';

const { thresholdPathLength: threshold } = config;

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

router.post('/cBlindPath', async (req, res) => {
    try {
        const id = req.body.id?.toString();
        const blindPath = req.body.blindPath; // array of { C_blind, proof }

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

        if (!blindPath || !Array.isArray(blindPath)) {
            return res.status(400).json({
                success: false,
                error: "Missing or invalid blindPath array. Expected array of { C_blind, proof }",
            });
        }

        const user = getUser(id);

        if (!user.pubKey) {
            return res.status(400).json({
                success: false,
                error: "User does not have a pubKey registered",
            });
        }

        if (!user.encryptedPath || !Array.isArray(user.encryptedPath)) {
            return res.status(400).json({
                success: false,
                error: "User does not have a stored encrypted path. Submit path first via POST /path",
            });
        }

        // if (blindPath.length > user.encryptedPath.length) {
        //     return res.status(400).json({
        //         success: false,
        //         error: `blindPath length (${blindPath.length}) exceeds stored encryptedPath length (${user.encryptedPath.length})`,
        //     });
        // }

        // if (isNaN(threshold) || threshold < 1) {
        //     return res.status(400).json({
        //         success: false,
        //         error: "threshold must be a positive integer",
        //     });
        // }

        // Verify each blind match proof against the stored encrypted path (prefix)
        const results = [];
        let matched = 0;

        for (let i = 0; i < blindPath.length; i++) {
            const { C_blind, proof } = blindPath[i];

            if (!C_blind || !proof || !proof.A || !proof.e || !proof.z_alpha || !proof.z_beta || !proof.z_gamma) {
                results.push({ index: i, valid: false, error: "Missing C_blind or proof fields" });
                break; // prefix broken
            }

            const valid = verifyBlindMatch(user.pubKey, user.encryptedPath[i], C_blind, proof);
            results.push({ index: i, valid });
            if (valid) matched++;
        }

        const verified = (matched === blindPath.length);

        if (verified) {
            storeUserBlindPath(id, blindPath.map(entry => entry.C_blind));
        }

        res.json({
            success: true,
            verified,
            id,
            matched,
            threshold,
            totalSegments: blindPath.length,
            results,
            message: verified
                ? `matched (${matched}/${blindPath.length}) Verified.`
                : `matched (${matched}/${blindPath.length}) Rejected.`,
        });
    } catch (error) {
        console.error("Blind path verification error:", error);
        res.status(500).json({
            success: false,
            verified: false,
            error: error.message,
        });
    }
});

export default router;
