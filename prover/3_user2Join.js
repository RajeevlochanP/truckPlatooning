import fs from "fs/promises";
import * as bls from '@noble/bls12-381';
import { proofGen, aggregateProofs } from './helpers/auth.helper.js';
import { proverBlindMatch } from './helpers/cBlind_path.helper.js';
import { priv_path_2 } from "../private/path.js"; // User 2's path

console.log("\n--- User 2 (Applicant) Joining User 1's Platoon ---");

// --- 1. BLS AUTH ---
console.log("\n1. Submitting BLS Identity Proof...");
const auth_sk_raw = JSON.parse(await fs.readFile("../private/auth_sk.json", "utf8"));
const auth_sk = auth_sk_raw.map(bytes => Uint8Array.from(bytes));
const message = "one-time-secret-identifier-13"; 
const h = new TextEncoder().encode(message);

const blsProofs = [];
for (const sk of auth_sk) blsProofs.push(await proofGen(h, sk));
const omegaAgg = aggregateProofs(blsProofs);

await fetch("http://localhost:3000/verify/auth", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ authProof: { omegaAgg: [...omegaAgg], h: [...h] }, id: "2" })
});
console.log("Auth verified.");

// --- 2. HE-PSI MATCHING ---
console.log("\n2. Fetching User 1's (Leader) and User 2's (Applicant) Encrypted Paths from chain...");
const leaderFetch = await fetch("http://localhost:3000/users/1/path");
const leaderData = await leaderFetch.json();
const leaderPath = leaderData.encryptedPath;

const applicantFetch = await fetch("http://localhost:3000/users/2/path");
const applicantData = await applicantFetch.json();
const applicantPath = applicantData.encryptedPath;

// Load Public Keys
const user1PubKey = JSON.parse(await fs.readFile("../public/paillier_pk.json", "utf8"));
const user2PubKey = JSON.parse(await fs.readFile("../public/paillier_pk.json", "utf8"));

// Load User 2's randomness saved from Phase 1
const user2Randoms = JSON.parse(await fs.readFile("../private/user2_randoms.json", "utf8"));

const matchLength = Math.min(leaderPath.length, priv_path_2.length);
console.log(`Computing Blind Evaluations over ${matchLength} segments...`);

const blindPath = [];
for (let i = 0; i < matchLength; i++) {
    const C_L = leaderPath[i];
    const C_A = applicantPath[i];
    const r_A = user2Randoms[i];
    const m_A = priv_path_2[i].toString();

    blindPath.push(proverBlindMatch(user1PubKey, user2PubKey, C_L, C_A, r_A, m_A));
}

console.log("Submitting Blind Path to Chain...");
const cBlindResponse = await fetch("http://localhost:3000/verify/cBlindPath", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
        applicantId: "2",
        leaderId: "1",
        blindPath
    })
});
const cBlindData = await cBlindResponse.json();
console.log("Chain response:", cBlindData.success ? "Blind Path Accepted!" : cBlindData.error);