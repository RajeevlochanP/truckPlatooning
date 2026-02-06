import fs from "fs/promises";
import * as bls from '@noble/bls12-381';
import * as paillierBigint from "paillier-bigint";
import { encryptPathAndGenerateProofs, verifyProof, randBetween } from './helpers/path.helper.js';
import { proofGen, aggregateProofs } from './helpers/auth.helper.js';
import { proverBlindMatch } from './helpers/cBlind_path.helper.js';
import { priv_path, priv_path_2 } from "../private/path.js";
import bigInt from 'big-integer';


// ============== Reconstruct Paillier public key =============
const pubKeyData = JSON.parse(
  await fs.readFile("../public/paillier_pk.json", "utf8")
);
const pubKey = new paillierBigint.PublicKey(BigInt(pubKeyData.n), BigInt(pubKeyData.g));
console.log("\n--- Paillier Public Key Reconstructed ---");


// Encrypt private path and generate proofs  
console.log("\n--- Encrypting Private Path ---");
const { encryptedPath, proofs } = encryptPathAndGenerateProofs(pubKey, priv_path);


// Verify proofs locally before sending to chain
console.log("\n--- Local Verification (Testing) ---");
let allLocalValid = true;
for (let i = 0; i < encryptedPath.length; i++) {
  const isValid = verifyProof(pubKey, encryptedPath[i], proofs[i]);
  console.log(`Segment ${i}: ${isValid ? '✓ Valid' : '✗ Invalid'}`);
  if (!isValid) allLocalValid = false;
}
if (!allLocalValid) {
  console.error("Local verification failed! Aborting.");
  process.exit(1);
}



// SEND TO CHAIN FOR VERIFICATION
console.log("\n--- Sending to Chain for Verification ---");

const pathResponse = await fetch("http://localhost:3000/verify/path", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    id: "1",
    encryptedPath,
    proofs,
  })
});

const pathData = await pathResponse.json();
console.log("Path verification response:", pathData);



await fs.writeFile(
  "../public/encrypted_path.json",
  JSON.stringify({ encryptedPath })
);

console.log("\n--- Encrypted path saved ---");


// ============== BLS AUTHENTICATION PROOF ==============
console.log("\n--- BLS Authentication Proof ---");

// Load auth keypair
const arr = JSON.parse(
  await fs.readFile("../private/auth_sk.json", "utf8")
);
const auth_sk = arr.map(bytes => Uint8Array.from(bytes));

const message = "one-time-secret-identifier-13"; // m

const h = new TextEncoder().encode(message);
const hPoint = await bls.PointG1.hashToCurve(h);

// Truck computes its one-time proof Omega_λ = h^sk
const blsProofs = [];
for (const sk of auth_sk) {
  const omega = await proofGen(h, sk);
  blsProofs.push(omega);
}

// Aggregate Omegas (G1) and PKs (G2)
const omegaAgg = aggregateProofs(blsProofs);

// Send the proof to chain for verification
const response_proof = await fetch("http://localhost:3000/verify/auth", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({ authProof: { omegaAgg: [...omegaAgg], h: [...h] }, id: "1" })
});

const authData = await response_proof.json();
console.log("Auth verification response:", authData);

// Write omegaAgg to file
await fs.writeFile(
  "../public/auth_proof.json",
  JSON.stringify({ omegaAgg: [...omegaAgg], h: [...h] })
);

// ============= Cblind Paillier Proof ==============


console.log("\n--- CBlind Paillier Proof ---");

// Fetch the stored encrypted path from the chain
const pathFetchResponse = await fetch("http://localhost:3000/users/1/path");
const pathFetchData = await pathFetchResponse.json();

if (!pathFetchData.success) {
  console.error("Failed to fetch encrypted path:", pathFetchData.error);
  process.exit(1);
}

const storedEncryptedPath = pathFetchData.encryptedPath;
console.log(`Fetched encrypted path from chain (length: ${storedEncryptedPath.length})`);
console.log(`Truck's private path_2 length: ${priv_path_2.length}`);

const n = BigInt(pubKeyData.n);
const n2 = n * n;

// Use the minimum length of both paths
const matchLength = Math.min(storedEncryptedPath.length, priv_path_2.length);
console.log(`Matching ${matchLength} segments...`);

const blindPath = [];
for (let i = 0; i < matchLength; i++) {
    const C_plat = storedEncryptedPath[i];
    const m = BigInt(priv_path_2[i]);

    // α: random secret scalar (mask) in [1, N)
    const alpha = BigInt(randBetween(bigInt(1), bigInt(n.toString())).toString());

    // β = -m * α  (masked path difference, as per protocol)
    const beta = -(m * alpha);

    // γ: random re-randomization factor in Z*_N
    const gamma = BigInt(randBetween(bigInt(1), bigInt(n.toString())).toString());

    blindPath.push(proverBlindMatch(
        { n: pubKeyData.n, g: pubKeyData.g },
        C_plat,
        alpha,
        beta,
        gamma
    ));
}

console.log("Blind path generated, sending to chain for verification...");

// Threshold: minimum number of matching prefix segments required
const threshold = matchLength;

const cBlindResponse = await fetch("http://localhost:3000/verify/cBlindPath", {
    method: "POST",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify({
        id: "1",
        blindPath,
        threshold,
    })
});

const cBlindData = await cBlindResponse.json();
console.log("CBlind path verification response:", cBlindData);






console.log("\n--- All Done! ---");