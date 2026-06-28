import crypto from 'crypto';
import bigInt from 'big-integer';

// Re-implementing modPow and modInverse locally for the prover
function modPow(base, exp, mod) {
    let b = BigInt(base) % BigInt(mod);
    let e = BigInt(exp);
    const m = BigInt(mod);
    let result = 1n;
    if (b < 0n) b += m;
    while (e > 0n) {
        if (e % 2n === 1n) result = (result * b) % m;
        b = (b * b) % m;
        e /= 2n;
    }
    return result;
}

function modInverse(a, m) {
    let [old_r, r] = [BigInt(a), BigInt(m)];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
        const quotient = old_r / r;
        [old_r, r] = [r, old_r - quotient * r];
        [old_s, s] = [s, old_s - quotient * s];
    }
    return (old_s % BigInt(m) + BigInt(m)) % BigInt(m);
}

function randBetween(min, max) {
    return bigInt.randBetween(min, max).toString();
}

export function generateDoubleBlindProof(pubKeyData, privKeyData, C_blind_str) {
    const n = BigInt(pubKeyData.n);
    const g = BigInt(pubKeyData.g);
    const lambda = BigInt(privKeyData.lambda);
    const n2 = n * n;
    
    const C_blind = BigInt(C_blind_str);

    // 1. Double-Blinding
    const r_P = BigInt(randBetween(bigInt(1), bigInt(n.toString())));
    const C_final = modPow(C_blind, r_P, n2);

    // 2. Decryption
    // Paillier decryption: L(C^lambda mod N^2) * mu mod N
    const L = (u) => (u - 1n) / n;
    const c_lambda = modPow(C_final, lambda, n2);
    const m_true = (L(c_lambda) * BigInt(privKeyData.mu)) % n;

    // 3. Isolate Randomness (R)
    // C_rand = C_final * g^{-m_true} mod N^2
    const g_m = modPow(g, m_true, n2);
    const g_m_inv = modInverse(g_m, n2);
    const C_rand = (C_final * g_m_inv) % n2;
    
    // R = C_rand^{N^-1 mod lambda} mod N
    const n_inv_lambda = modInverse(n, lambda);
    // Since C_rand = r^N mod N^2, to find r mod N, we take (C_rand mod N)^(n_inv_lambda) mod N
    const R = modPow(C_rand % n, n_inv_lambda, n);

    // 4. Generate ZKP (Algorithm 3)
    const s = BigInt(randBetween(bigInt(1), bigInt((n2 / 2n).toString())));
    const A_plat = modPow(C_blind, s, n2);

    const hash = crypto.createHash('sha256');
    hash.update(n.toString());
    hash.update(C_blind.toString());
    hash.update(C_final.toString());
    hash.update(A_plat.toString());
    const e_plat = BigInt('0x' + hash.digest('hex'));

    const z_plat = s + (e_plat * r_P);

    return {
        m_true: m_true.toString(),
        R: R.toString(),
        C_final: C_final.toString(),
        proof: {
            A_plat: A_plat.toString(),
            e_plat: e_plat.toString(),
            z_plat: z_plat.toString()
        }
    };
}