import { initialize } from "zokrates-js";
import fs from "fs/promises";
import * as bls from '@noble/bls12-381';
import bigInt from 'big-integer';
import crypto from 'crypto';

const zokratesProvider = await initialize();

// load zk artifacts and keypair
const zk_artifacts = JSON.parse(
  await fs.readFile("./public/zk_artifacts.json", "utf8")
);
zk_artifacts.program = Buffer.from(zk_artifacts.program, "base64");

let pk = JSON.parse(
  await fs.readFile("./private/prover_key.json", "utf8")
);

if (!Array.isArray(pk) && typeof pk === 'object') {
  pk = Object.values(pk);
}
pk = new Uint8Array(pk);

// load public and private paths
import {adj, pub_path, pub_len, h_adj, hash_pubpath} from "./public/graph.js";
import {priv_path, priv_len} from "./private/path.js";

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

function proverGenerateProof(pubKey, m, r, C) {
    const { n, g, n2 } = pubKey;

    // 1. Commitment Phase
    // Pick random rho in [0, n]
    const rho = randBetween(bigInt(0), n);
    // Pick random s in [1, n) (must be coprime to n, usually safe if random)
    const s = randBetween(bigInt(1), n);

    // A = g^rho * s^n mod n^2
    const g_rho = g.modPow(rho, n2);
    const s_n = s.modPow(n, n2);
    const A = g_rho.multiply(s_n).mod(n2);

    // 2. Challenge Phase (Fiat-Shamir)
    const e = generateChallenge(n, g, C, A);

    // 3. Response Phase
    // z1 = rho + e * m (Note: Standard integer addition, NOT modulo)
    const z1 = rho.add(e.multiply(m));

    // z2 = s * r^e mod n
    const r_e = r.modPow(e, n);
    const z2 = s.multiply(r_e).mod(n);

    console.log("-> Prover: Proof generated.");
    
    // Return the proof tuple
    return { 
        A: A.toString(), 
        e: e.toString(), 
        z1: z1.toString(), 
        z2: z2.toString() 
    };
}


const inputs = [
  adj,          // 256-element array
  pub_path,     // 16-element array
  pub_len,          // pub_len
  "2",          // min_sublen
  hash_pubpath,          // hash_pubpath
  h_adj,          // hash_adj
  priv_path,    // 16-element array
  priv_len          // priv_len
];

let witness, output, proof;

try{

    // computation
     ({ witness, output } = zokratesProvider.computeWitness(zk_artifacts, inputs));

    // generate proof
    proof = zokratesProvider.generateProof(
      zk_artifacts.program,
      witness,
      pk
    );

    //write witness to file
    await fs.writeFile(
    "./private/witness.json",
    JSON.stringify(witness)
    );

    //write proof and output to file
    await fs.writeFile(
    "./public/proof.json",
    JSON.stringify(proof)
    );
    await fs.writeFile(
    "./public/output.json",
    JSON.stringify(output)
    );
  
}
catch(err){
  console.error("Error during proof generation:", err);
}

// send proof to chain for verification
const response = await fetch("http://localhost:3000/verify/path", {
    method: "POST",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify({ proof, output })
});

let respData = await response.json();
console.log("Response from chain:", respData);

// BLS part for authentication proof

async function proofGen(h, sk) {
    const omega = await bls.sign(h, sk); // = h^sk
    return omega;
}

function aggregateProofs(proofs) {
    return bls.aggregateSignatures(proofs);
}


// load auth keypair
const arr = JSON.parse(
  await fs.readFile("./private/auth_sk.json", "utf8")
);
const auth_sk = arr.map(bytes => Uint8Array.from(bytes));

const message = "one-time-secret-identifier-13"; // m

const h = new TextEncoder().encode(message);
const hPoint = await bls.PointG1.hashToCurve(h);

// Truck computes its one-time proof Omega_λ = h^sk
const proofs = [];
//   const h = oneTimeHash(message);
for (const sk of auth_sk) {
    
    const omega = await proofGen(h, sk);
    proofs.push(omega);
}

// Aggregate Omegas (G1) and PKs (G2)
const omegaAgg = aggregateProofs(proofs);

// send the proof to chain for verification
const response_proof = await fetch("http://localhost:3000/verify/auth", {
    method: "POST",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify({ omegaAgg: [...omegaAgg], h: [...h], id: "1" })
});

respData = await response_proof.json();
console.log("Response from chain:", respData);

//write omegaAgg to file
await fs.writeFile(
  "./public/auth_proof.json",
  JSON.stringify({omegaAgg: [...omegaAgg], h:[...h]})
);