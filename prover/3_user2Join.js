import fs from "fs/promises";
import * as bls from '@noble/bls12-381';
import bigInt from 'big-integer';
import { proofGen, aggregateProofs } from './helpers/auth.helper.js';
import { proverBlindMatch } from './helpers/cBlind_path.helper.js';
import { randBetween } from './helpers/path.helper.js';
import { priv_path_2 } from "../private/path.js"; // User 2's path

console.log("\n--- User 2 (Applicant) Joining User 1's Platoon ---");

// --- 1. BLS AUTH ---
console.log("\n1. Submitting BLS Identity Proof...");
const auth_sk_raw = JSON.parse(await fs.readFile("../private/user2_auth_sk.json", "utf8"));
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
console.log("\n2. Fetching User 1's Encrypted Path from chain...");
const pathFetch = await fetch("http://localhost:3000/users/1/path");
const pathData = await pathFetch.json();
const leaderPath = pathData.encryptedPath;

// We need USER 1's Paillier Public Key to compute the homomorphic difference
const user1PubKey = JSON.parse(await fs.readFile("../public/user1_paillier_pk.json", "utf8"));
const n = BigInt(user1PubKey.n);

const matchLength = Math.min(leaderPath.length, priv_path_2.length);
console.log(`Computing Blind Evaluations over ${matchLength} segments...`);

const blindPath = [];
for (let i = 0; i < matchLength; i++) {
    const C_plat = leaderPath[i];
    const m = BigInt(priv_path_2[i]);
    const alpha = BigInt(randBetween(bigInt(1), bigInt(n.toString())).toString());
    const beta = -(m * alpha);
    const gamma = BigInt(randBetween(bigInt(1), bigInt(n.toString())).toString());

    blindPath.push(proverBlindMatch(
        { n: user1PubKey.n, g: user1PubKey.g },
        C_plat, alpha, beta, gamma
    ));
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