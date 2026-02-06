import fs from "fs/promises";
import * as dotenv from "dotenv";
import * as bls from '@noble/bls12-381';
import * as paillierBigint from "paillier-bigint";
import { numberOfCompanies, paillierBitLength } from "./parameters.js";

dotenv.config({ quiet: true });





// ============== PAILLIER PUBLIC KEY SETUP ==============
const { publicKey, privateKey } = await paillierBigint.generateRandomKeys(paillierBitLength);

// Serialize pubKey for storage and chain registration
const serializedPubKey = {
  n: publicKey.n.toString(),
  g: publicKey.g.toString(),
};

const serializedPrivKey = {
  lambda: privateKey.lambda.toString(),
  mu: privateKey.mu.toString(),
};






// ============== BLS AUTH KEYPAIR SETUP ==============

function keyGen() {
    const sk = bls.utils.randomPrivateKey();   // α
    const pk = bls.getPublicKey(sk);           // g^α
    return { sk, pk };
}

// CA: create key pair for `numberOfCompanies` company fleet for 1 truck
const authKeypair = {pk: [], sk: []};
for (let i = 0; i < numberOfCompanies; i++) {
    const { sk, pk } = keyGen();
    authKeypair.pk.push(pk);
    authKeypair.sk.push(sk);
}

const serialized_pk = authKeypair.pk.map(pk => [...pk]);
const serialized_sk = authKeypair.sk.map(sk => [...sk]);




// ============== REGISTER USER ON CHAIN ==============


const response = await fetch("http://localhost:3000/register", {
    method: "POST",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify({ authPks: serialized_pk, pubKey: serializedPubKey, id: 1 })
});
const data = await response.json();

console.log("Registration response: ", data);





// ============== LOCAL STORAGE ================

// Save auth keys locally (for prover to use later)
await fs.writeFile(
  "../public/auth_pk.json",
  JSON.stringify(serialized_pk)
);
await fs.writeFile(
  "../private/auth_sk.json",
  JSON.stringify(serialized_sk)
);

// Save paillier keys locally (for prover to use later)
await fs.writeFile(
  "../public/paillier_pk.json",
  JSON.stringify(serializedPubKey)
);
await fs.writeFile(
    "../private/paillier_sk.json",
    JSON.stringify(serializedPrivKey)
);
console.log("======Paillier keys saved locally.======");