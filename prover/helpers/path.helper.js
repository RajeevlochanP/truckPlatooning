import crypto from 'crypto';
import * as paillierBigint from "paillier-bigint";

// Helper functions for native BigInt
export function modPow(base, exp, mod) {
    let b = BigInt(base) % BigInt(mod);
    let e = BigInt(exp);
    const m = BigInt(mod);
    let result = 1n;
    if (b < 0n) b += m;
    if (e < 0n) {
        e = -e;
        b = modInverse(b, m); 
    }
    while (e > 0n) {
        if (e % 2n === 1n) result = (result * b) % m;
        b = (b * b) % m;
        e /= 2n;
    }
    return result;
}

export function modInverse(a, m) {
    let [old_r, r] = [BigInt(a), BigInt(m)];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
        const quotient = old_r / r;
        [old_r, r] = [r, old_r - quotient * r];
        [old_s, s] = [s, old_s - quotient * s];
    }
    return (old_s % BigInt(m) + BigInt(m)) % BigInt(m);
}

export function randBetween(min, max) {
    const minBn = BigInt(min);
    const maxBn = BigInt(max);
    const range = maxBn - minBn;
    const hex = range.toString(16);
    const byteLength = Math.ceil(hex.length / 2);
    let randomNum;
    do {
        const buffer = crypto.randomBytes(byteLength);
        randomNum = BigInt('0x' + buffer.toString('hex'));
    } while (randomNum >= range);
    return randomNum + minBn;
}

export function generateChallenge(N, g, C, A) {
    const hash = crypto.createHash('sha256');
    hash.update(N.toString());
    hash.update(g.toString());
    hash.update(C.toString());
    hash.update(A.toString());
    return BigInt('0x' + hash.digest('hex'));
}

export function generateProof(pubKey, m, r, C) {
    const n = BigInt(pubKey.n);
    const g = BigInt(pubKey.g);
    const n2 = n * n;
    const message = BigInt(m);
    const randomness = BigInt(r);
    const ciphertext = BigInt(C);

    // ------ 1. Commitment Phase ------
    // Pick random rho in [0, 2^128 * n]
    const rhoMax = n * (1n << 128n);
    const rho = randBetween(0n, rhoMax);
    // Pick random s in [1, n)
    const s = randBetween(1n, n);

    // A = g^rho * s^n mod n^2
    const g_rho = modPow(g, rho, n2);
    const s_n = modPow(s, n, n2);
    const A = (g_rho * s_n) % n2;

    // ------ 2. Challenge Phase (Fiat-Shamir) ------
    const e = generateChallenge(n, g, ciphertext, A);

    // ------ 3. Response Phase ------
    // z1 = rho + e * m (Note: Standard integer addition, NOT modulo)
    const z1 = rho + (e * message);

    // z2 = s * r^e mod n
    const r_e = modPow(randomness, e, n);
    const z2 = (s * r_e) % n;

    return { 
        A: A.toString(), 
        e: e.toString(), 
        z1: z1.toString(), 
        z2: z2.toString() 
    };
}

export function encryptPathAndGenerateProofs(pubKey, pathArray) {
    const encryptedPath = [];
    const proofs = [];
    const randoms = [];

    pathArray.forEach((segment) => {
        const m = BigInt(segment);
        const r = randBetween(1n, BigInt(pubKey.n));
        const C = pubKey.encrypt(m, r);
        
        const proof = generateProof(pubKey, m, r, C);
        
        encryptedPath.push(C.toString());
        proofs.push(proof);
        randoms.push(r.toString());
    });

    return {
        encryptedPath,
        proofs,
        randoms
    };
}

export function verifyProof(pubKey, C, proof) {
    const n = BigInt(pubKey.n);
    const g = BigInt(pubKey.g);
    const n2 = n * n;
    
    const A = BigInt(proof.A);
    const e = BigInt(proof.e);
    const z1 = BigInt(proof.z1);
    const z2 = BigInt(proof.z2);
    const ciphertext = BigInt(C);

    // 1. Verify Challenge Integrity
    const e_check = generateChallenge(n, g, ciphertext, A);
    
    if (e !== e_check) {
        return false;
    }

    // 2. Verify Mathematical Equality
    // LHS = g^z1 * z2^n mod n^2
    const g_z1 = modPow(g, z1, n2);
    const z2_n = modPow(z2, n, n2);
    const LHS = (g_z1 * z2_n) % n2;

    // RHS = A * C^e mod n^2
    const C_e = modPow(ciphertext, e, n2);
    const RHS = (A * C_e) % n2;

    return LHS === RHS;
}