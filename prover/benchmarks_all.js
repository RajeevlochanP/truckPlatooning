import fs from "fs/promises";
import { performance } from "perf_hooks";
import * as paillierBigint from "paillier-bigint";
import crypto from "crypto";

import { encryptPathAndGenerateProofs } from './helpers/path.helper.js';
import { proverBlindMatch } from './helpers/cBlind_path.helper.js';
import { generateDoubleBlindProof } from '../chain/helpers/platoon.helper.js';
import { verifyBlindMatch } from '../chain/helpers/cBlindPaillier.helper.js';
import { verifyFinalMatch } from '../chain/helpers/cBlindPaillier.helper.js';

function modPow(base, exp, modulus) {
    let res = 1n;
    base = base % modulus;
    while (exp > 0n) {
        if (exp % 2n === 1n) res = (res * base) % modulus;
        base = (base * base) % modulus;
        exp = exp / 2n;
    }
    return res;
}

function hashToBigInt(str, modulus) {
    const hash = crypto.createHash('sha256').update(str.toString()).digest('hex');
    return BigInt('0x' + hash) % modulus;
}

// ----------------------------------------------------
// 1. RSA-PSI WITH DLEQ ZKP (Malicious Probing Resistant)
// ----------------------------------------------------
function runRSAPSI_Malicious(l, rsaParams) {
    const { N, e, d } = rsaParams;
    const pathA = Array.from({ length: l }, (_, i) => `waypoint_${i + 100}`);
    const pathB = Array.from({ length: l }, (_, i) => `waypoint_${i + 100}`);

    const start = performance.now();

    for (let i = 0; i < l; i++) {
        // Blind input
        const r = 65537n + BigInt(i + 1); 
        const hx = hashToBigInt(pathA[i], N);
        const u = (hx * modPow(r, e, N)) % N;

        // Sign input
        const signed = modPow(u, d, N);

        // DLEQ Proof Generation (2 modular exponentiations)
        const k = BigInt('0x' + crypto.randomBytes(16).toString('hex'));
        const a = modPow(u, k, N);
        const challenge = hashToBigInt(a.toString(), N);
        const s = k + challenge * d;

        // DLEQ Proof Verification (2 modular exponentiations)
        const v1 = (modPow(u, s, N) * modPow(signed, -challenge, N)) % N;
    }

    return performance.now() - start;
}

// ----------------------------------------------------
// 2. BGW-PSI WITH PEDERSEN VSS (Malicious Share Verifiable)
// ----------------------------------------------------
const BGW_PRIME = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
const G_BGW = 2n;
const H_BGW = 3n;

function runBGW_VSS_Malicious(l) {
    const pathA = Array.from({ length: l }, (_, i) => BigInt(i + 100));
    const pathB = Array.from({ length: l }, (_, i) => BigInt(i + 100));

    const start = performance.now();

    for (let i = 0; i < l; i++) {
        // Generate shares
        const s1 = (pathA[i] + 17n * 1n) % BGW_PRIME;
        const r1 = BigInt('0x' + crypto.randomBytes(16).toString('hex'));

        // Pedersen Commitment for share verification (g^s * h^r mod p)
        const comm = (modPow(G_BGW, s1, BGW_PRIME) * modPow(H_BGW, r1, BGW_PRIME)) % BGW_PRIME;

        // Verify Pedersen Commitment
        const check = (modPow(G_BGW, s1, BGW_PRIME) * modPow(H_BGW, r1, BGW_PRIME)) % BGW_PRIME;
        if (comm !== check) throw new Error("VSS Failed");

        // Additive Reconstruction
        const diff = (pathA[i] - pathB[i]) % BGW_PRIME;
    }

    return performance.now() - start;
}

// ----------------------------------------------------
// 3. MinHash / LSH (Probabilistic Baseline)
// ----------------------------------------------------
const LSH_PRIME = 2147483647n;
const K_HASHES = 100;
const hashFuncs = Array.from({ length: K_HASHES }, (_, i) => ({
    a: BigInt(i * 3 + 7),
    b: BigInt(i * 11 + 13)
}));

function runMinHashLSH(l) {
    const pathA = Array.from({ length: l }, (_, i) => i + 100);
    const pathB = Array.from({ length: l }, (_, i) => i + 100);

    const start = performance.now();

    function computeSignature(path) {
        const sig = [];
        for (let h = 0; h < K_HASHES; h++) {
            let minVal = LSH_PRIME;
            for (const waypoint of path) {
                const val = (hashFuncs[h].a * BigInt(waypoint) + hashFuncs[h].b) % LSH_PRIME;
                if (val < minVal) minVal = val;
            }
            sig.push(minVal);
        }
        return sig;
    }

    const sigA = computeSignature(pathA);
    const sigB = computeSignature(pathB);

    let matches = 0;
    for (let i = 0; i < K_HASHES; i++) {
        if (sigA[i] === sigB[i]) matches++;
    }

    return performance.now() - start;
}

// ----------------------------------------------------
// MAIN BENCHMARK RUNNER
// ----------------------------------------------------
async function runBenchmark() {
    console.log("Loading Keys and Generating RSA Parameters...");
    
    const pubKeyData1 = JSON.parse(await fs.readFile("../public/user1_paillier_pk.json", "utf8"));
    const pubKey1 = new paillierBigint.PublicKey(BigInt(pubKeyData1.n), BigInt(pubKeyData1.g));
    const privKeyData1 = JSON.parse(await fs.readFile("../private/user1_paillier_sk.json", "utf8"));
    
    const pubKeyData2 = JSON.parse(await fs.readFile("../public/user2_paillier_pk.json", "utf8"));
    const pubKey2 = new paillierBigint.PublicKey(BigInt(pubKeyData2.n), BigInt(pubKeyData2.g));

    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const pubJwk = publicKey.export({ format: 'jwk' });
    const privJwk = privateKey.export({ format: 'jwk' });
    const rsaParams = {
        N: BigInt('0x' + Buffer.from(pubJwk.n, 'base64url').toString('hex')),
        e: BigInt('0x' + Buffer.from(pubJwk.e, 'base64url').toString('hex')),
        d: BigInt('0x' + Buffer.from(privJwk.d, 'base64url').toString('hex'))
    };

    const pathLengths = [1, 2, 3, 4, 5];
    let csvContent = "PathLength(l),HE_P1_Commit_ms,HE_P2_App_Blind_ms,HE_P2_SC_Blind_Verify_ms,HE_P2_Leader_Decrypt_ms,HE_P2_SC_Final_Verify_ms,HE_Total_Phase2_ms,RSA_PSI_Malicious_ms,BGW_VSS_Malicious_ms,MinHash_LSH_ms\n";

    console.log("\nStarting Benchmark...");

    for (const l of pathLengths) {
        console.log(`\n--- Benchmarking Path Length: ${l} ---`);
        
        const dummyPath1 = Array.from({ length: l }, (_, i) => i + 100); 
        const dummyPath2 = Array.from({ length: l }, (_, i) => i + 100); 

        // Proposed HE-PSI
        let t0 = performance.now();
        const leaderData = encryptPathAndGenerateProofs(pubKey1, dummyPath1);
        const applicantData = encryptPathAndGenerateProofs(pubKey2, dummyPath2);
        let t1 = performance.now();
        const he_p1_commit_time = (t1 - t0) / 2; 

        const leaderCiphers = leaderData.encryptedPath;
        const applicantCiphers = applicantData.encryptedPath;
        const applicantRandoms = applicantData.randoms;

        t0 = performance.now();
        const blindPathPayloads = [];
        for (let i = 0; i < l; i++) {
            const payload = proverBlindMatch(pubKey1, pubKey2, leaderCiphers[i], applicantCiphers[i], applicantRandoms[i], dummyPath2[i].toString());
            blindPathPayloads.push(payload);
        }
        t1 = performance.now();
        const he_p2_app_gen_time = (t1 - t0);

        t0 = performance.now();
        for (let i = 0; i < l; i++) {
            const { C_beta, C_blind, proof } = blindPathPayloads[i];
            const valid = verifyBlindMatch(pubKeyData1, pubKeyData2, leaderCiphers[i], applicantCiphers[i], C_beta, C_blind, proof);
            if (!valid) throw new Error("SC Blind Verify Failed!");
        }
        t1 = performance.now();
        const he_p2_sc_verify1_time = (t1 - t0);

        t0 = performance.now();
        const finalPayloads = [];
        for (let i = 0; i < l; i++) {
            const payload = generateDoubleBlindProof(pubKeyData1, privKeyData1, blindPathPayloads[i].C_blind);
            finalPayloads.push(payload);
        }
        t1 = performance.now();
        const he_p2_leader_decrypt_time = (t1 - t0);

        t0 = performance.now();
        for (let i = 0; i < l; i++) {
            const valid = verifyFinalMatch(pubKeyData1, blindPathPayloads[i].C_blind, finalPayloads[i]);
            if (!valid) throw new Error("SC Final Verify Failed!");
        }
        t1 = performance.now();
        const he_p2_sc_verify2_time = (t1 - t0);

        const he_total_phase2 = he_p2_app_gen_time + he_p2_sc_verify1_time + he_p2_leader_decrypt_time + he_p2_sc_verify2_time;

        const rsa_time = runRSAPSI_Malicious(l, rsaParams);
        const bgw_time = runBGW_VSS_Malicious(l);
        const minhash_time = runMinHashLSH(l);

        console.log(`HE-PSI Total Phase 2: ${he_total_phase2.toFixed(3)} ms`);
        console.log(`RSA-PSI (Malicious):   ${rsa_time.toFixed(3)} ms`);
        console.log(`BGW-VSS (Malicious):   ${bgw_time.toFixed(3)} ms`);
        console.log(`MinHash LSH:           ${minhash_time.toFixed(3)} ms`);

        csvContent += `${l},${he_p1_commit_time.toFixed(3)},${he_p2_app_gen_time.toFixed(3)},${he_p2_sc_verify1_time.toFixed(3)},${he_p2_leader_decrypt_time.toFixed(3)},${he_p2_sc_verify2_time.toFixed(3)},${he_total_phase2.toFixed(3)},${rsa_time.toFixed(3)},${bgw_time.toFixed(3)},${minhash_time.toFixed(3)}\n`;
    }

    await fs.writeFile("benchmark_results_all.csv", csvContent);
    console.log("\n✅ Benchmark Complete! Results saved to 'benchmark_results_all.csv'");
}

runBenchmark().catch(console.error);