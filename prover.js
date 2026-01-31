import { initialize } from "zokrates-js";
import fs from "fs/promises";
import * as bls from '@noble/bls12-381';

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