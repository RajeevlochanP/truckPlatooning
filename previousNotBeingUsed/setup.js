import fs from "fs/promises";
import { initialize } from "zokrates-js";
import * as dotenv from "dotenv";
import * as bls from '@noble/bls12-381';
import { id } from "ethers";
import bigInt from 'big-integer';
import crypto from 'crypto';

dotenv.config({ quiet: true });
const zokratesProvider = await initialize();

// ============== PAILLIER PUBLIC KEY SETUP ==============
const p = bigInt(499);
const q = bigInt(547);
const n = p.multiply(q);
const n2 = n.square();
const g = n.add(1);
const pubKey = { n, g, n2 };

// Serialize pubKey for storage and chain registration
const serializedPubKey = {
  n: n.toString(),
  g: g.toString(),
  n2: n2.toString(),
};

// Save pubKey locally (for prover to use later)
await fs.writeFile(
  "./public/pub_key.json",
  JSON.stringify(serializedPubKey)
);
console.log("Paillier public key saved locally.");

// // load zk artifacts
// const zk_artifacts = JSON.parse(
//   await fs.readFile("./public/zk_artifacts.json", "utf8")
// );
// zk_artifacts.program = Buffer.from(zk_artifacts.program, "base64");

// // run setup
// const keypair = zokratesProvider.setup(zk_artifacts.program);
// // console.log(keypair);



// //write keypair to file

// // prover key
// await fs.writeFile(
//   "./private/prover_key.json",
//   JSON.stringify(keypair.pk)
// );

// // verifier key
// await fs.writeFile(
//   "./public/verifier_key.json",
//   JSON.stringify(keypair.vk)
// );

// send verifier key to chain
// const response_vk = await fetch("http://localhost:3000/verifier-key", {
//     method: "POST",
//     headers: {
//         "Content-Type": "application/json"
//     },
//     body: JSON.stringify({ vk: keypair.vk })
// });


// // export solidity verifier
// const verifier = zokratesProvider.exportSolidityVerifier(keypair.vk);
// //write verifier to file
// await fs.writeFile(
//   "./public/verifier.sol",
//   verifier
// );



function keyGen() {
    const sk = bls.utils.randomPrivateKey();   // α
    const pk = bls.getPublicKey(sk);           // g^α
    return { sk, pk };
}

// CA: create key pair for 3 company fleet for 1 truck
const authKeypair = {pk: [], sk: []};
for (let i = 0; i < 3; i++) {
    const { sk, pk } = keyGen();
    authKeypair.pk.push(pk);
    authKeypair.sk.push(sk);
}

const serialized_pk = authKeypair.pk.map(pk => [...pk]);


// Auth keypair for one-time use
await fs.writeFile(
  "./public/auth_pk.json",
  JSON.stringify(serialized_pk)
);

// send auth pk's and pubKey to chain
const response = await fetch("http://localhost:3000/register", {
    method: "POST",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify({ authPks: serialized_pk, pubKey: serializedPubKey, id: 1 })
});
const data = await response.json();

console.log("Registration response: ", data);

const serialized_sk = authKeypair.sk.map(sk => [...sk]);

await fs.writeFile(
  "./private/auth_sk.json",
  JSON.stringify(serialized_sk)
);
