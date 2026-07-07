import * as crypto from 'crypto';

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

export function generateChallenge(C_A, C_L, C_beta, C_blind, A1, A2, A3) {
    const hash = crypto.createHash('sha256');
    hash.update(C_A.toString());
    hash.update(C_L.toString());
    hash.update(C_beta.toString());
    hash.update(C_blind.toString());
    hash.update(A1.toString());
    hash.update(A2.toString());
    hash.update(A3.toString());
    const hexDigest = hash.digest('hex');
    return BigInt('0x' + hexDigest);
}

export function proverBlindMatch(pubKeyLeader, pubKeyApplicant, C_L_str, C_A_str, r_A_str, m_A_str) {
    const N_L = BigInt(pubKeyLeader.n);
    const g_L = BigInt(pubKeyLeader.g);
    const N_L2 = N_L * N_L;
    
    const N_A = BigInt(pubKeyApplicant.n);
    const g_A = BigInt(pubKeyApplicant.g);
    const N_A2 = N_A * N_A;

    const C_L = BigInt(C_L_str);
    const C_A = BigInt(C_A_str);
    const r_A = BigInt(r_A_str);
    const m_A = BigInt(m_A_str);

    // 1. Sample alpha, gamma, r_u
    const alpha = randBetween(1n, N_L);
    const gamma = randBetween(1n, N_L);
    const r_u = randBetween(1n, N_A);

    // 2. Compute beta = -m_A * alpha (Negative BigInt over Z)
    const beta = -(m_A * alpha);
    const beta_abs = -beta; // The positive magnitude of beta

    // 3. Compute r_v = r_A^(-alpha) * r_u mod N_A
    const r_A_inv = modInverse(r_A, N_A);
    const r_A_inv_alpha = modPow(r_A_inv, alpha, N_A);
    const r_v = (r_A_inv_alpha * r_u) % N_A;

    // 4. Compute C_beta = C_A^(-alpha) * r_u^(N_A) mod N_A^2
    const C_A_inv = modInverse(C_A, N_A2);
    const c_a_inv_alpha = modPow(C_A_inv, alpha, N_A2);
    const r_u_N_A = modPow(r_u, N_A, N_A2);
    const C_beta = (c_a_inv_alpha * r_u_N_A) % N_A2;

    // 5. Compute C_blind = C_L^alpha * g_L^beta * gamma^(N_L) mod N_L^2
    const c_l_alpha = modPow(C_L, alpha, N_L2);
    const g_L_inv = modInverse(g_L, N_L2);
    const g_l_beta = modPow(g_L_inv, beta_abs, N_L2); // Raise inverse to positive beta_abs
    const gamma_N_L = modPow(gamma, N_L, N_L2);
    const C_blind = (((c_l_alpha * g_l_beta) % N_L2) * gamma_N_L) % N_L2;

    // --- ZKP pi_eval Generation ---
    // Sample r_alpha in [0, 2^128 * N_L], r_beta in [0, 2^128 * N_A]
    const r_alpha_max = N_L * (1n << 128n);
    const r_alpha = randBetween(0n, r_alpha_max);

    // STATISTICAL HIDING FIX: r_beta must dominate (e * beta) to keep z_beta positive!
    // Assuming 'e' is a 256-bit hash, its max value is ~2^256. 
    // We multiply by 2^128 for the lambda hiding factor.
    const e_max = 1n << 256n; 
    const r_beta_max = (beta_abs * e_max) * (1n << 128n); 
    const r_beta = randBetween(0n, r_beta_max);

    // Sample r_s1, r_s2 in Z*_N_A, r_s3 in Z*_N_L
    const r_s1 = randBetween(1n, N_A);
    const r_s2 = randBetween(1n, N_A);
    const r_s3 = randBetween(1n, N_L);

    // A1 = C_A^(-r_alpha) * r_s1^(N_A) mod N_A^2
    const a1_term1 = modPow(C_A_inv, r_alpha, N_A2); // Safely use C_A_inv from earlier
    const a1_term2 = modPow(r_s1, N_A, N_A2);
    const A1 = (a1_term1 * a1_term2) % N_A2;

    // A2 = g_A^(r_beta) * r_s2^(N_A) mod N_A^2
    const a2_term1 = modPow(g_A, r_beta, N_A2);
    const a2_term2 = modPow(r_s2, N_A, N_A2);
    const A2 = (a2_term1 * a2_term2) % N_A2;

    // A3 = C_L^(r_alpha) * g_L^(r_beta) * r_s3^(N_L) mod N_L^2
    const a3_term1 = modPow(C_L, r_alpha, N_L2);
    const a3_term2 = modPow(g_L, r_beta, N_L2);
    const a3_term3 = modPow(r_s3, N_L, N_L2);
    const A3 = (((a3_term1 * a3_term2) % N_L2) * a3_term3) % N_L2;

    // Challenge e
    const e = generateChallenge(C_A, C_L, C_beta, C_blind, A1, A2, A3);

    // Integer Responses (over Z)
    const z_alpha = r_alpha + (e * alpha);
    const z_beta = r_beta + (e * beta);

    // Modulo Responses
    const z1 = (r_s1 * modPow(r_u, e, N_A)) % N_A;
    const z2 = (r_s2 * modPow(r_v, e, N_A)) % N_A;
    const z3 = (r_s3 * modPow(gamma, e, N_L)) % N_L;

    // ==========================================
    // INTERNAL PROVER SANITY CHECK (EQUATION 1)
    // ==========================================
    const eq1_lhs = modPow(z1, N_A, N_A2);
    const eq1_rhs_1 = (A1 * modPow(C_beta, e, N_A2)) % N_A2;
    const eq1_rhs = (eq1_rhs_1 * modPow(C_A, z_alpha, N_A2)) % N_A2;
    
    if (eq1_lhs !== eq1_rhs) {
        console.error("❌ CRITICAL: Prover failed its own math check!");
        console.log(`LHS: ${eq1_lhs}\nRHS: ${eq1_rhs}`);
        process.exit(1);
    } else {
        console.log("✅ Prover Internal Math Check Passed.");
    }
    // ==========================================

    return {
        C_beta: C_beta.toString(),
        C_blind: C_blind.toString(),
        proof: {
            A1: A1.toString(),
            A2: A2.toString(),
            A3: A3.toString(),
            e: e.toString(),
            z_alpha: z_alpha.toString(),
            z_beta: z_beta.toString(),
            z1: z1.toString(),
            z2: z2.toString(),
            z3: z3.toString()
        }
    };
}