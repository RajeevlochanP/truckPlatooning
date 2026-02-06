import fs from "fs/promises";
import { initialize } from "zokrates-js";
import * as bls from '@noble/bls12-381';


// Read proof and output from files
const proof = JSON.parse(
  await fs.readFile("./public/proof.json", "utf8")
);

const output = JSON.parse(
  await fs.readFile("./public/output.json", "utf8")
);

const zokratesProvider = await initialize();

const vk = JSON.parse(
  await fs.readFile("./public/verifier_key.json", "utf8")
);


const isVerifiedPath = zokratesProvider.verify(
  vk,
  proof,
  output
);

console.log(` Path Verification completed successfully. result: ${isVerifiedPath}`);


function aggregatePKs(pks) {
    return bls.aggregatePublicKeys(pks);
}

async function verifyProof(omega, h, pk) {
    return await bls.verify(omega, h, pk);
}

// Read auth proofs and pks from files
const authProof = JSON.parse(
  await fs.readFile("./public/auth_proof.json", "utf8")
);

const omegaAgg = Uint8Array.from(authProof.omegaAgg);
const hash = Uint8Array.from(authProof.h);


const arr = JSON.parse(
  await fs.readFile("./public/auth_pk.json", "utf8")
);
const authPks = arr.map(bytes => Uint8Array.from(bytes));

const pkAgg = aggregatePKs(authPks);



// Verify
const isVerifiedAuth = await verifyProof(omegaAgg, hash, pkAgg);


console.log(` Auth Verification completed successfully. result: ${isVerifiedAuth}`);
