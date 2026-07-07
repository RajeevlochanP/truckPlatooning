import fs from "fs/promises";
import * as paillierBigint from "paillier-bigint";
import { encryptPathAndGenerateProofs } from './helpers/path.helper.js';
import { priv_path } from "../private/path.js"; // User 1's path

console.log("\n--- User 1 (PL) Committing Path ---");

// User 1 encrypts with their OWN public key
const pubKeyData = JSON.parse(await fs.readFile("../public/user1_paillier_pk.json", "utf8"));
const pubKey = new paillierBigint.PublicKey(BigInt(pubKeyData.n), BigInt(pubKeyData.g));

console.log("Encrypting Private Path...");
const { encryptedPath, proofs, randoms } = encryptPathAndGenerateProofs(pubKey, priv_path);

console.log("Saving User 1's Randomness Locally...");
await fs.writeFile("../private/user1_randoms.json", JSON.stringify(randoms));

console.log("Sending to Chain...");
const pathResponse = await fetch("http://localhost:3000/verify/path", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
        id: "1",
        encryptedPath,
        proofs,
    })
});

const pathData = await pathResponse.json();
console.log("Chain response:", pathData.message);
console.log("User 1 is now a Platoon Leader of size 1!");