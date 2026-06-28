import fs from "fs/promises";
import * as dotenv from "dotenv";
import * as bls from '@noble/bls12-381';
import * as paillierBigint from "paillier-bigint";
import { numberOfCompanies, paillierBitLength } from "./parameters.js";

dotenv.config({ quiet: true });

async function generateUserKeys(userId) {
    console.log(`Generating keys for User ${userId}...`);
    // Paillier Keys
    const { publicKey, privateKey } = await paillierBigint.generateRandomKeys(paillierBitLength);
    const serializedPubKey = { n: publicKey.n.toString(), g: publicKey.g.toString() };
    const serializedPrivKey = { lambda: privateKey.lambda.toString(), mu: privateKey.mu.toString() };

    // BLS Keys
    const authKeypair = { pk: [], sk: [] };
    for (let i = 0; i < numberOfCompanies; i++) {
        const sk = bls.utils.randomPrivateKey();
        authKeypair.pk.push([...bls.getPublicKey(sk)]);
        authKeypair.sk.push([...sk]);
    }

    // Save to public/private folders with prefixes
    await fs.writeFile(`../public/user${userId}_auth_pk.json`, JSON.stringify(authKeypair.pk));
    await fs.writeFile(`../private/user${userId}_auth_sk.json`, JSON.stringify(authKeypair.sk));
    await fs.writeFile(`../public/user${userId}_paillier_pk.json`, JSON.stringify(serializedPubKey));
    await fs.writeFile(`../private/user${userId}_paillier_sk.json`, JSON.stringify(serializedPrivKey));
    console.log(`User ${userId} keys saved locally.\n`);
}

// Generate for User 1 (Leader) and User 2 (Applicant)
await generateUserKeys(1);
await generateUserKeys(2);
console.log("====== All keys generated successfully. ======");