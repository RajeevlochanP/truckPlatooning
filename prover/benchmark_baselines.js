import fs from "fs/promises";
import { performance } from "perf_hooks";
import crypto from "crypto";

// ==========================================
// 1. MALICIOUS ECC-PSI (ECDH + DLEQ ZKPs)
// ==========================================
// To achieve Malicious Security, standard ECC-PSI must attach a Discrete 
// Logarithm Equality (DLEQ) Zero-Knowledge Proof to every encrypted waypoint.
// This requires roughly 5 Elliptic Curve scalar multiplications per waypoint.

function runMalicious_ECC_PSI(l) {
    const start = performance.now();
    
    // Simulate the exact time cost of EC scalar multiplications using native ECDH
    // 5 operations per waypoint (Hash-to-curve, Blind, ZKP Gen, ZKP Verify x2)
    const operationsPerWaypoint = 5; 
    
    for (let i = 0; i < l * operationsPerWaypoint; i++) {
        // Generate an ephemeral ECDH keypair as a proxy for one EC scalar multiplication
        crypto.createECDH('secp256k1').generateKeys();
    }

    const duration = performance.now() - start;
    return duration;
}

// ==========================================
// 2. MALICIOUS OT-PSI (Garbled Bloom Filters)
// ==========================================
// Malicious OT-PSI uses highly optimized symmetric cryptography (AES/Hash).
// The computation is extremely fast, but the communication payload is massive.

function runMalicious_OT_PSI(l) {
    const start = performance.now();
    
    // In OT-PSI, the computation is dominated by symmetric AES encryptions 
    // for the Oblivious Transfer extension (approx. 128 AES ops per waypoint).
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    for (let i = 0; i < l * 128; i++) {
        const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
        cipher.update(Buffer.alloc(16));
        cipher.final();
    }

    const duration = performance.now() - start;
    return duration;
}

// ==========================================
// MAIN BENCHMARK RUNNER
// ==========================================
async function runBaselines() {
    const pathLengths = [10, 20, 30, 40, 50];
    let csvContent = "PathLength(l),Malicious_ECC_PSI_ms,Malicious_OT_PSI_ms\n";

    console.log("\nStarting Malicious Baselines Benchmark...");

    for (const l of pathLengths) {
        const eccTime = runMalicious_ECC_PSI(l);
        const otTime = runMalicious_OT_PSI(l);
        
        console.log(`Length: ${l} | ECC-PSI (DLEQ): ${eccTime.toFixed(2)} ms | OT-PSI (GBF): ${otTime.toFixed(2)} ms`);
        csvContent += `${l},${eccTime.toFixed(3)},${otTime.toFixed(3)}\n`;
    }

    await fs.writeFile("benchmark_malicious_baselines.csv", csvContent);
    console.log("\n✅ Benchmark Complete! Results saved to 'benchmark_malicious_baselines.csv'");
}

runBaselines().catch(console.error);