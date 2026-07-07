import fs from "fs/promises";
import * as paillierBigint from "paillier-bigint";
import { encryptPathAndGenerateProofs } from './helpers/path.helper.js';
import { priv_path_2 } from "../private/path.js"; // User 2's path

console.log("\n--- User 2 (Applicant) Committing Path ---");

// User 2 encrypts with their OWN public key
const pubKeyData = JSON.parse(await fs.readFile("../public/user2_paillier_pk.json", "utf8"));
const pubKey = new paillierBigint.PublicKey(BigInt(pubKeyData.n), BigInt(pubKeyData.g));

console.log("Encrypting Private Path (User 2)...");
// We need randoms (r_A) to be saved for Phase 2
const { encryptedPath, proofs, randoms } = encryptPathAndGenerateProofs(pubKey, priv_path_2);

console.log("Saving User 2's Randomness Locally for Phase 2...");
await fs.writeFile("../private/user2_randoms.json", JSON.stringify(randoms));

console.log("Sending to Chain...");
const pathResponse = await fetch("http://localhost:3000/verify/path", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
        id: "2",
        encryptedPath,
        proofs,
    })
});

const pathData = await pathResponse.json();
console.log("Chain response:", pathData.message);
console.log("User 2 successfully committed their path to the server!");
