import * as crypto from 'crypto';
import bigInt from 'big-integer';
import { randBetween } from '../helpers/path.helper.js';

export function modPow(base, exp, mod) {
    let b = base % mod;
    let e = exp;
    let result = 1n;
    
    // Handle negative base
    if (b < 0n) b += mod;

    // Handle negative exponent (Modular Inverse)
    if (e < 0n) {
        // Simplified inversion for N^2 (Paillier) where gcd(base, mod) is likely 1
        // In prod, use a proper Extended Euclidean Algo function
        // For g=N+1, inverse is 1-N. For general cases, this placeholder warns:
        e = -e;
        b = modInverse(b, mod); 
    }

    while (e > 0n) {
        if (e % 2n === 1n) result = (result * b) % mod;
        b = (b * b) % mod;
        e /= 2n;
    }
    return result;
}

export function modInverse(a, m) {
    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];
    
    while (r !== 0n) {
        const quotient = old_r / r;
        [old_r, r] = [r, old_r - quotient * r];
        [old_s, s] = [s, old_s - quotient * s];
    }
    
    if (old_r > 1n) throw new Error('Inverse does not exist');
    return (old_s % m + m) % m;
}

export function generateChallenge(n, C_plat, C_blind, A) {
    const hash = crypto.createHash('sha256');
    
    hash.update(n.toString());
    hash.update(C_plat.toString());
    hash.update(C_blind.toString());
    hash.update(A.toString());
    
    const hexDigest = hash.digest('hex');
    return BigInt('0x' + hexDigest);
}

export function proverBlindMatch(pubKey, C_plat, alpha, beta, gamma) {
    const n = BigInt(pubKey.n);
    const g = BigInt(pubKey.g);
    const C_p = BigInt(C_plat);
    const a = BigInt(alpha);
    const b = BigInt(beta);
    const gam = BigInt(gamma);
    
    const n2 = n * n;

    // 1. Compute C_blind (The result of the operation)
    // C_blind = C_plat^alpha * g^beta * gamma^N
    const term1 = modPow(C_p, a, n2);
    const term2 = modPow(g, b, n2);
    const term3 = modPow(gam, n, n2);
    const C_blind = (term1 * term2 * term3) % n2;

    // 2. Commitment Phase
    const r_alpha = BigInt(randBetween(bigInt(0), bigInt(n.toString())).toString());
    const r_beta  = BigInt(randBetween(bigInt(0), bigInt(n.toString())).toString());
    const r_gamma = BigInt(randBetween(bigInt(1), bigInt(n.toString())).toString());

    // A = C_plat^r_alpha * g^r_beta * r_gamma^N mod N^2
    const A1 = modPow(C_p, r_alpha, n2);
    const A2 = modPow(g, r_beta, n2);
    const A3 = modPow(r_gamma, n, n2);
    const A = (A1 * A2 * A3) % n2;

    // 3. Challenge Phase
    const e = generateChallenge(n, C_p, C_blind, A);

    // 4. Response Phase
    // z_alpha = r_alpha + e * alpha
    const z_alpha = r_alpha + (e * a);

    // z_beta = r_beta + e * beta 
    const z_beta = r_beta + (e * b);

    // z_gamma = r_gamma * gamma^e mod N
    const gamma_e = modPow(gam, e, n);
    const z_gamma = (r_gamma * gamma_e) % n;

    return {
        C_blind: C_blind.toString(),
        proof: {
            A: A.toString(),
            e: e.toString(),
            z_alpha: z_alpha.toString(),
            z_beta: z_beta.toString(),
            z_gamma: z_gamma.toString()
        }
    };
}