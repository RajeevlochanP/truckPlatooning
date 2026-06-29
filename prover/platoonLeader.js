import fs from "fs/promises";
import { generateDoubleBlindProof } from "./helpers/platoon.helper.js";

async function runPlatoonLeader() {
    console.log("\n[PLATOON LEADER] Starting Verification Process...");

    // 1. Load keys (Leader uses its own private key, assuming shared params here for demo)
    const pubKeyData = JSON.parse(await fs.readFile("../public/paillier_pk.json", "utf8"));
    const privKeyData = JSON.parse(await fs.readFile("../private/paillier_sk.json", "utf8"));

    const leaderId = "Leader_99";
    const applicantId = "1"; // The ID used in prover.js

    // 2. Fetch the Applicant's Blind Path from the Chain
    console.log(`[PLATOON LEADER] Fetching blind path for applicant ${applicantId} from chain...`);
    const fetchRes = await fetch(`http://localhost:3000/users/${applicantId}/blindPath`);
    const fetchData = await fetchRes.json();

    if (!fetchData.success) {
        console.error("Failed to fetch blind path:", fetchData.error);
        process.exit(1);
    }

    const blindPath = fetchData.blindPath;
    console.log(`[PLATOON LEADER] Fetched ${blindPath.length} segments.`);

    // 3. Process each segment (Double-Blind & Decrypt)
    console.log("[PLATOON LEADER] Generating Double-Blind Proofs...");
    const finalPaths = [];

    for (let i = 0; i < blindPath.length; i++) {
        const C_blind = blindPath[i];
        const payload = generateDoubleBlindProof(pubKeyData, privKeyData, C_blind);
        finalPaths.push(payload);
    }

    // 4. Send to Chain for Final Validation and Platoon Join
    console.log("[PLATOON LEADER] Submitting final proofs to chain for admission...");
    const verifyRes = await fetch("http://localhost:3000/verify/finalMatch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            leaderId,
            applicantId,
            finalPaths
        })
    });

    const verifyData = await verifyRes.json();
    console.log("\n=== SMART CONTRACT DECISION ===");
    console.log(verifyData);
    console.log("===============================\n");
}

runPlatoonLeader();