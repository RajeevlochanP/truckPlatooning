import fs from "fs/promises";
import * as paillierBigint from "paillier-bigint";

// --- IMPORTS (Adjust paths if necessary) ---
import { encryptPathAndGenerateProofs } from './helpers/path.helper.js';
import { proverBlindMatch } from './helpers/cBlind_path.helper.js';

async function runPayloadBenchmark() {
    console.log("Loading Keys...");
    const pubKeyData1 = JSON.parse(await fs.readFile("../public/user1_paillier_pk.json", "utf8"));
    const pubKey1 = new paillierBigint.PublicKey(BigInt(pubKeyData1.n), BigInt(pubKeyData1.g));
    
    const pubKeyData2 = JSON.parse(await fs.readFile("../public/user2_paillier_pk.json", "utf8"));
    const pubKey2 = new paillierBigint.PublicKey(BigInt(pubKeyData2.n), BigInt(pubKeyData2.g));

    const pathLengths = [10, 20, 30, 40, 50];
    
    // NEW CSV HEADER: Separating the components
    let csvContent = "PathLength(l),Metadata_Bytes,C_beta_Bytes,C_blind_Bytes,ZKP_Bytes,Total_Bytes,Total_KB\n";

    console.log("\nStarting Strict Payload Size Benchmark...");

    for (const l of pathLengths) {
        const dummyPath1 = Array.from({ length: l }, (_, i) => i + 100);
        const dummyPath2 = Array.from({ length: l }, (_, i) => i + 100);

        const leaderData = encryptPathAndGenerateProofs(pubKey1, dummyPath1);
        const applicantData = encryptPathAndGenerateProofs(pubKey2, dummyPath2);

        const leaderCiphers = leaderData.encryptedPath;
        const applicantCiphers = applicantData.encryptedPath;
        const applicantRandoms = applicantData.randoms;

        const blindPathArray = [];
        const justC_beta = [];
        const justC_blind = [];
        const justProofs = [];

        for (let i = 0; i < l; i++) {
            const rawPayload = proverBlindMatch(
                pubKey1, pubKey2, 
                leaderCiphers[i], applicantCiphers[i], 
                applicantRandoms[i], dummyPath2[i].toString()
            );

            // STRICT FILTERING: Only transmit what the paper mathematically dictates.
            // This guarantees we don't accidentally send public keys or debug data.
            const cleanProof = {
                A1: rawPayload.proof.A1.toString(),
                A2: rawPayload.proof.A2.toString(),
                A3: rawPayload.proof.A3.toString(),
                e: rawPayload.proof.e.toString(),
                z_alpha: rawPayload.proof.z_alpha.toString(),
                z_beta: rawPayload.proof.z_beta.toString(),
                z1: rawPayload.proof.z1.toString(),
                z2: rawPayload.proof.z2.toString(),
                z3: rawPayload.proof.z3.toString()
            };

            const cleanElement = {
                C_beta: rawPayload.C_beta.toString(),
                C_blind: rawPayload.C_blind.toString(),
                proof: cleanProof
            };

            blindPathArray.push(cleanElement);

            // Store individually just for exact CSV measurement
            justC_beta.push(cleanElement.C_beta);
            justC_blind.push(cleanElement.C_blind);
            justProofs.push(cleanElement.proof);
        }

        // The exact final payload sent over the HTTP/V2X network
        const requestPayload = {
            applicantId: "2",
            leaderId: "1",
            blindPath: blindPathArray
        };

        // Measure each component in Bytes
        const metaBytes = Buffer.byteLength(JSON.stringify({ applicantId: "2", leaderId: "1" }), 'utf8');
        const cBetaBytes = Buffer.byteLength(JSON.stringify(justC_beta), 'utf8');
        const cBlindBytes = Buffer.byteLength(JSON.stringify(justC_blind), 'utf8');
        const zkpBytes = Buffer.byteLength(JSON.stringify(justProofs), 'utf8');
        
        // Measure Total
        const totalBytes = Buffer.byteLength(JSON.stringify(requestPayload), 'utf8');
        const totalKb = totalBytes / 1024;

        // Append to CSV
        csvContent += `${l},${metaBytes},${cBetaBytes},${cBlindBytes},${zkpBytes},${totalBytes},${totalKb.toFixed(2)}\n`;
        
        console.log(`Path Length: ${l} | Total: ${totalKb.toFixed(2)} KB (ZKP takes ${zkpBytes} Bytes)`);
    }

    await fs.writeFile("benchmark_payload.csv", csvContent);
    console.log("\n✅ Payload Benchmark Complete! Results saved to 'benchmark_payload.csv'");
}

runPayloadBenchmark().catch(console.error);