import bigInt from 'big-integer';
import crypto from 'crypto';
import * as paillierBigint from "paillier-bigint";

/**
 * Generate a random BigInt between min (inclusive) and max (exclusive)
 */
export function randBetween(min, max) {
    const range = max.minus(min);
    const byteLength = Math.ceil(range.bitLength() / 8);
    let randomNum;
    do {
        const buffer = crypto.randomBytes(byteLength);
        const hex = buffer.toString('hex');
        randomNum = bigInt(hex, 16);
    } while (randomNum.geq(range));
    return randomNum.add(min);
}

/**
 * Fiat-Shamir Challenge Generator
 * Hashes inputs (N, g, C, A) to create a non-interactive challenge 'e'
 */
export function generateChallenge(N, g, C, A) {
    const hash = crypto.createHash('sha256');
    hash.update(N.toString());
    hash.update(g.toString());
    hash.update(C.toString());
    hash.update(A.toString());
    
    const hex = hash.digest('hex');
    return bigInt(hex, 16);
}

export function generateProof(pubKey, m, r, C) {
    const n = bigInt(pubKey.n.toString());
    const g = bigInt(pubKey.g.toString());
    const n2 = bigInt(pubKey._n2.toString());
    const message = bigInt(m.toString());
    const randomness = bigInt(r.toString());
    const ciphertext = bigInt(C.toString());

    // ------ 1. Commitment Phase ------
    // Pick random rho in [0, n]
    const rho = randBetween(bigInt(0), n);
    // Pick random s in [1, n) (must be coprime to n, usually safe if random)
    const s = randBetween(bigInt(1), n);

    // A = g^rho * s^n mod n^2
    const g_rho = g.modPow(rho, n2);
    const s_n = s.modPow(n, n2);
    const A = g_rho.multiply(s_n).mod(n2);


    // ------ 2. Challenge Phase (Fiat-Shamir) ------
    const e = generateChallenge(n, g, ciphertext, A);


    // ------ 3. Response Phase ------
    // z1 = rho + e * m (Note: Standard integer addition, NOT modulo)
    const z1 = rho.add(e.multiply(message));

    // z2 = s * r^e mod n
    const r_e = randomness.modPow(e, n);
    const z2 = s.multiply(r_e).mod(n);

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

    pathArray.forEach((segment) => {
        const m = bigInt(segment);
        const r = randBetween(bigInt(1), bigInt(pubKey.n.toString()));
        const C = pubKey.encrypt(BigInt(m.toString()), BigInt(r.toString()));
        
        const proof = generateProof(pubKey, m, r, C);
        
        encryptedPath.push(C.toString());
        proofs.push(proof);
    });

    return {
        encryptedPath,
        proofs,
    };
}

/**
 * Verify a single proof (for local testing)
 */
export function verifyProof(pubKey, C, proof) {
    const n = bigInt(pubKey.n.toString());
    const g = bigInt(pubKey.g.toString());
    const n2 = bigInt(pubKey._n2.toString());
    
    const A = bigInt(proof.A);
    const e = bigInt(proof.e);
    const z1 = bigInt(proof.z1);
    const z2 = bigInt(proof.z2);
    const ciphertext = bigInt(C);

    // 1. Verify Challenge Integrity
    const e_check = generateChallenge(n, g, ciphertext, A);
    
    if (e.neq(e_check)) {
        return false;
    }

    // 2. Verify Mathematical Equality
    // LHS = g^z1 * z2^n mod n^2
    const g_z1 = g.modPow(z1, n2);
    const z2_n = z2.modPow(n, n2);
    const LHS = g_z1.multiply(z2_n).mod(n2);

    // RHS = A * C^e mod n^2
    const C_e = ciphertext.modPow(e, n2);
    const RHS = A.multiply(C_e).mod(n2);

    return LHS.eq(RHS);
}