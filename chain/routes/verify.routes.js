import { Router } from 'express';
import { verifyAuthProof, verifyPathProofs, verifyBlindMatch,verifyFinalMatch } from '../helpers/index.js';
import { getUser, hasUser, storeUserPath, storeUserBlindPath,addToPlatoon,getPlatoon } from '../store/index.js';
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
    // Inside POST /path, replace the successful save block with:
    if (allValid) {
      storeUserPath(id, encryptedPath);
      addToPlatoon(id, id); // User creates a platoon of size 1 with themselves
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
        const { applicantId, leaderId, blindPath } = req.body;

        if (!applicantId || !leaderId || !blindPath) {
            return res.status(400).json({ success: false, error: "Missing applicantId, leaderId, or blindPath" });
        }

        const applicant = getUser(applicantId);
        const leader = getUser(leaderId);

        if (!applicant || !leader) {
            return res.status(404).json({ success: false, error: "Applicant or Leader not found" });
        }
        if (!leader.encryptedPath) {
            return res.status(400).json({ success: false, error: "Leader has no encrypted path" });
        }

        const results = [];
        let matched = 0;

        for (let i = 0; i < blindPath.length; i++) {
            const { C_blind, proof } = blindPath[i];
            // CRITICAL: We use the LEADER's pubKey and LEADER's encrypted path!
            const valid = verifyBlindMatch(leader.pubKey, leader.encryptedPath[i], C_blind, proof);
            results.push({ index: i, valid });
            if (valid) matched++;
        }

        const verified = (matched === blindPath.length);

        if (verified) {
            // Save the blind path to the APPLICANT's profile
            storeUserBlindPath(applicantId, blindPath.map(entry => entry.C_blind));
        }

        res.json({
            success: true, verified, applicantId, leaderId, matched, totalSegments: blindPath.length, results
        });
    } catch (error) {
        console.error("Blind path error:", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

router.post('/finalMatch', async (req, res) => {
    try {
        const { leaderId, applicantId, finalPaths } = req.body;

        if (!leaderId || !applicantId || !finalPaths) {
            return res.status(400).json({ success: false, error: "Missing required fields." });
        }

        const applicant = getUser(applicantId);
        if (!applicant || !applicant.hasBlindPath) {
            return res.status(400).json({ success: false, error: "Applicant has no blind path." });
        }

        // Assume leader uses same paillier pubkey for this demo
        const pubKey = applicant.pubKey; 
        
        let validCount = 0;
        let matchCount = 0;
        const results = [];

        for (let i = 0; i < finalPaths.length; i++) {
            const C_blind = applicant.blindPath[i];
            const payload = finalPaths[i];

            // Verify math
            const isValid = verifyFinalMatch(pubKey, C_blind, payload);
            results.push({ index: i, valid: isValid, m_true: payload.m_true });
            
            if (isValid) {
                validCount++;
                // If m_true == 0, the routes are exactly the same
                if (payload.m_true === "0") {
                    matchCount++;
                }
            }
        }

        const isFullyVerified = (validCount === finalPaths.length);
        const isRouteMatched = (matchCount === finalPaths.length);

        if (isFullyVerified && isRouteMatched) {
            addToPlatoon(leaderId, applicantId);
        }

        res.json({
            success: true,
            verified: isFullyVerified,
            matched: isRouteMatched,
            platoon: getPlatoon(leaderId),
            message: isRouteMatched 
                ? `Applicant ${applicantId} successfully joined Platoon ${leaderId}` 
                : "Route mismatch, rejected.",
            results
        });

    } catch (error) {
        console.error("Final match error:", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

export default router;
