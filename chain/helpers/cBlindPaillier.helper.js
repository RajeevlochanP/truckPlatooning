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
    if (old_r > 1n) throw new Error('Inverse does not exist');
    return (old_s % BigInt(m) + BigInt(m)) % BigInt(m);
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
    return BigInt('0x' + hash.digest('hex'));
}

export function verifyBlindMatch(pubKeyLeader, pubKeyApplicant, C_L_str, C_A_str, C_beta_str, C_blind_str, proof) {
    const N_L = BigInt(pubKeyLeader.n);
    const g_L = BigInt(pubKeyLeader.g);
    const N_L2 = N_L * N_L;

    const N_A = BigInt(pubKeyApplicant.n);
    const g_A = BigInt(pubKeyApplicant.g);
    const N_A2 = N_A * N_A;

    const C_L = BigInt(C_L_str);
    const C_A = BigInt(C_A_str);
    const C_beta = BigInt(C_beta_str);
    const C_blind = BigInt(C_blind_str);

    const A1 = BigInt(proof.A1);
    const A2 = BigInt(proof.A2);
    const A3 = BigInt(proof.A3);
    const e = BigInt(proof.e);
    const z_alpha = BigInt(proof.z_alpha);
    const z_beta = BigInt(proof.z_beta);
    const z1 = BigInt(proof.z1);
    const z2 = BigInt(proof.z2);
    const z3 = BigInt(proof.z3);

    // 1. Recompute Challenge
    const e_check = generateChallenge(C_A, C_L, C_beta, C_blind, A1, A2, A3);
    if (e !== e_check) {
        console.error("Hash Mismatch: Integrity check failed.");
        return false;
    }

    // 2. Verify Equation 1: z_1^{N_A} == A_1 * C_beta^e * C_A^{z_alpha} mod N_A^2
    const eq1_lhs = modPow(z1, N_A, N_A2);
    const eq1_rhs_1 = (A1 * modPow(C_beta, e, N_A2)) % N_A2;
    const eq1_rhs = (eq1_rhs_1 * modPow(C_A, z_alpha, N_A2)) % N_A2;
    if (eq1_lhs !== eq1_rhs) {
        console.error("Equation 1 Verification Failed.");
        return false;
    }

    // 3. Verify Equation 2: g_A^{z_beta} * z_2^{N_A} == A_2 * C_beta^e mod N_A^2
    const eq2_lhs_1 = modPow(g_A, z_beta, N_A2);
    const eq2_lhs_2 = modPow(z2, N_A, N_A2);
    const eq2_lhs = (eq2_lhs_1 * eq2_lhs_2) % N_A2;
    const eq2_rhs = (A2 * modPow(C_beta, e, N_A2)) % N_A2;
    if (eq2_lhs !== eq2_rhs) {
        console.error("Equation 2 Verification Failed.");
        return false;
    }

    // 4. Verify Equation 3: C_L^{z_alpha} * g_L^{z_beta} * z_3^{N_L} == A_3 * C_blind^e mod N_L^2
    const eq3_lhs_1 = modPow(C_L, z_alpha, N_L2);
    const eq3_lhs_2 = modPow(g_L, z_beta, N_L2);
    const eq3_lhs_3 = modPow(z3, N_L, N_L2);
    const eq3_lhs = (((eq3_lhs_1 * eq3_lhs_2) % N_L2) * eq3_lhs_3) % N_L2;
    const eq3_rhs = (A3 * modPow(C_blind, e, N_L2)) % N_L2;
    if (eq3_lhs !== eq3_rhs) {
        console.error("Equation 3 Verification Failed.");
        return false;
    }

    console.log("Proof Verified: Blind Calculation Correct.");
    return true;
}

export function generateFinalChallenge(n, C_blind, C_final, A_plat) {
    const hash = crypto.createHash('sha256');
    hash.update(n.toString());
    hash.update(C_blind.toString());
    hash.update(C_final.toString());
    hash.update(A_plat.toString());
    return BigInt('0x' + hash.digest('hex'));
}

export function verifyFinalMatch(pubKey, C_blind_str, finalPayload) {
    const n = BigInt(pubKey.n.toString());
    const g = BigInt(pubKey.g.toString());
    const n2 = n * n;

    const C_blind = BigInt(C_blind_str);
    const m_true = BigInt(finalPayload.m_true);
    const R = BigInt(finalPayload.R);
    const C_final = BigInt(finalPayload.C_final);
    
    const A_plat = BigInt(finalPayload.proof.A_plat);
    const e_plat = BigInt(finalPayload.proof.e_plat);
    const z_plat = BigInt(finalPayload.proof.z_plat);

    // 1. Recompute Challenge
    const e_check = generateFinalChallenge(n, C_blind, C_final, A_plat);
    if (e_plat !== e_check) {
        console.error("Final Hash Mismatch: Integrity check failed.");
        return false;
    }

    // 2. Verify ZKP Exponentiation Binding (C_blind^z_plat == A_plat * C_final^e_plat)
    const lhs_bind = modPow(C_blind, z_plat, n2);
    const rhs_bind = (A_plat * modPow(C_final, e_plat, n2)) % n2;
    if (lhs_bind !== rhs_bind) {
        console.error("ZKP Binding Verification Failed.");
        return false;
    }

    // 3. Verify Deterministic Decryption (g^m_true * R^N == C_final)
    const lhs_dec1 = modPow(g, m_true, n2);
    const lhs_dec2 = modPow(R, n, n2);
    const lhs_dec = (lhs_dec1 * lhs_dec2) % n2;
    
    if (lhs_dec !== C_final) {
        console.error("Deterministic Decryption Verification Failed.");
        return false;
    }

    return true;
}