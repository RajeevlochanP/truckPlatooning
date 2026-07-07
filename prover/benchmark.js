import fs from "fs/promises";
import { performance } from "perf_hooks";
import * as paillierBigint from "paillier-bigint";

import { encryptPathAndGenerateProofs } from './helpers/path.helper.js';
import { proverBlindMatch } from './helpers/cBlind_path.helper.js';
import { generateDoubleBlindProof } from '../chain/helpers/platoon.helper.js';
import { verifyBlindMatch } from '../chain/helpers/cBlindPaillier.helper.js';
import { verifyFinalMatch } from '../chain/helpers/cBlindPaillier.helper.js';

async function runBenchmark() {
    console.log("Loading Keys...");
    // Load User 1 (Leader)
    const pubKeyData1 = JSON.parse(await fs.readFile("../public/user1_paillier_pk.json", "utf8"));
    const pubKey1 = new paillierBigint.PublicKey(BigInt(pubKeyData1.n), BigInt(pubKeyData1.g));
    const privKeyData1 = JSON.parse(await fs.readFile("../private/user1_paillier_sk.json", "utf8"));
    
    // Load User 2 (Applicant)
    const pubKeyData2 = JSON.parse(await fs.readFile("../public/user2_paillier_pk.json", "utf8"));
    const pubKey2 = new paillierBigint.PublicKey(BigInt(pubKeyData2.n), BigInt(pubKeyData2.g));

    // Define path lengths to test (to prove O(l) linearity)
    const pathLengths = [10, 20, 50, 100, 200, 500, 1000];
    
    // CSV Header
    let csvContent = "PathLength(l),P1_Commit_Gen_ms,P2_App_Blind_Gen_ms,P2_SC_Blind_Verify_ms,P2_Leader_Decrypt_Gen_ms,P2_SC_Final_Verify_ms,Total_Phase2_ms\n";

    console.log("\nStarting Benchmark...");

    for (const l of pathLengths) {
        console.log(`\n--- Benchmarking Path Length: ${l} ---`);
        
        // 1. Generate Dummy Paths of length l
        const dummyPath1 = Array.from({ length: l }, (_, i) => i + 100); // e.g., [100, 101, ...]
        const dummyPath2 = Array.from({ length: l }, (_, i) => i + 100); // Perfect match for testing

        // ==========================================
        // PHASE 1: Route Commitment Generation
        // ==========================================
        let t0 = performance.now();
        const leaderData = encryptPathAndGenerateProofs(pubKey1, dummyPath1);
        const applicantData = encryptPathAndGenerateProofs(pubKey2, dummyPath2);
        let t1 = performance.now();
        const p1_commit_time = (t1 - t0) / 2; // Average time for one user to commit 'l' segments

        const leaderCiphers = leaderData.encryptedPath;
        const applicantCiphers = applicantData.encryptedPath;
        const applicantRandoms = applicantData.randoms;

        // ==========================================
        // PHASE 2: Applicant Generates C_beta, C_blind, and ZKP
        // ==========================================
        t0 = performance.now();
        const blindPathPayloads = [];
        for (let i = 0; i < l; i++) {
            const payload = proverBlindMatch(pubKey1, pubKey2, leaderCiphers[i], applicantCiphers[i], applicantRandoms[i], dummyPath2[i].toString());
            blindPathPayloads.push(payload);
        }
        t1 = performance.now();
        const p2_app_gen_time = (t1 - t0);

        // ==========================================
        // PHASE 2: SC Verifies Applicant's 3 Equations
        // ==========================================
        t0 = performance.now();
        for (let i = 0; i < l; i++) {
            const { C_beta, C_blind, proof } = blindPathPayloads[i];
            const valid = verifyBlindMatch(pubKeyData1, pubKeyData2, leaderCiphers[i], applicantCiphers[i], C_beta, C_blind, proof);
            if (!valid) throw new Error("SC Blind Verify Failed during benchmark!");
        }
        t1 = performance.now();
        const p2_sc_verify1_time = (t1 - t0);

        // ==========================================
        // PHASE 2: Leader Double-Blinds & Decrypts
        // ==========================================
        t0 = performance.now();
        const finalPayloads = [];
        for (let i = 0; i < l; i++) {
            const payload = generateDoubleBlindProof(pubKeyData1, privKeyData1, blindPathPayloads[i].C_blind);
            finalPayloads.push(payload);
        }
        t1 = performance.now();
        const p2_leader_decrypt_time = (t1 - t0);

        // ==========================================
        // PHASE 2: SC Verifies Final Decryption
        // ==========================================
        t0 = performance.now();
        for (let i = 0; i < l; i++) {
            const valid = verifyFinalMatch(pubKeyData1, blindPathPayloads[i].C_blind, finalPayloads[i]);
            if (!valid) throw new Error("SC Final Verify Failed during benchmark!");
        }
        t1 = performance.now();
        const p2_sc_verify2_time = (t1 - t0);

        // Calculate total Phase 2 time
        const total_phase2 = p2_app_gen_time + p2_sc_verify1_time + p2_leader_decrypt_time + p2_sc_verify2_time;

        // Append to CSV
        csvContent += `${l},${p1_commit_time.toFixed(3)},${p2_app_gen_time.toFixed(3)},${p2_sc_verify1_time.toFixed(3)},${p2_leader_decrypt_time.toFixed(3)},${p2_sc_verify2_time.toFixed(3)},${total_phase2.toFixed(3)}\n`;
        
        console.log(`P2 Total Time: ${total_phase2.toFixed(3)} ms`);
    }

    // Write CSV to file
    await fs.writeFile("benchmark_results1.csv", csvContent);
    console.log("\n✅ Benchmark Complete! Results saved to 'benchmark_results1.csv'");
}

runBenchmark().catch(console.error);