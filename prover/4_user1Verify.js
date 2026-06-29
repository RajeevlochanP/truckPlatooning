import fs from "fs/promises";
import { generateDoubleBlindProof } from "./helpers/platoon.helper.js";

console.log("\n--- User 1 (PL) Verifying Applicant 2 ---");

// User 1 uses their OWN keys to decrypt
const pubKeyData = JSON.parse(await fs.readFile("../public/user1_paillier_pk.json", "utf8"));
const privKeyData = JSON.parse(await fs.readFile("../private/user1_paillier_sk.json", "utf8"));

console.log("Fetching User 2's Blind Path from chain...");
const fetchRes = await fetch(`http://localhost:3000/users/2/blindPath`);
const fetchData = await fetchRes.json();
const blindPath = fetchData.blindPath;

console.log("Double-Blinding and Decrypting locally...");
const finalPaths = [];
for (let i = 0; i < blindPath.length; i++) {
    finalPaths.push(generateDoubleBlindProof(pubKeyData, privKeyData, blindPath[i]));
}

console.log("Submitting final result to chain for admission...");
const verifyRes = await fetch("http://localhost:3000/verify/finalMatch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
        leaderId: "1",
        applicantId: "2",
        finalPaths
    })
});

const verifyData = await verifyRes.json();
console.log("\n=== SMART CONTRACT PLATOON DECISION ===");
console.log(verifyData.message);
console.log("Current Platoon Array:", verifyData.platoon);
console.log("=======================================\n");