import fs from "fs/promises";

async function registerUser(userId) {
    const authPks = JSON.parse(await fs.readFile(`../public/user${userId}_auth_pk.json`, "utf8"));
    const pubKey = JSON.parse(await fs.readFile(`../public/user${userId}_paillier_pk.json`, "utf8"));

    const response = await fetch("http://localhost:3000/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ authPks, pubKey, id: userId.toString() })
    });
    const data = await response.json();
    console.log(`User ${userId} Registration:`, data.message || data.error);
}

console.log("--- Registering Users on Chain ---");
await registerUser(1);
await registerUser(2);