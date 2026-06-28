import * as crypto from 'crypto';
export function generateChallenge(n, C_plat, C_blind, A) {
    const hash = crypto.createHash('sha256');
    
    // Feed inputs deterministically (Order matters!)
    hash.update(n.toString());
    hash.update(C_plat.toString());
    hash.update(C_blind.toString());
    hash.update(A.toString());
    
    // Get hex digest and convert to BigInt
    const hexDigest = hash.digest('hex');
    return BigInt('0x' + hexDigest);
}

export function modPow(base, exp, mod) {
    let b = BigInt(base) % BigInt(mod);
    let e = BigInt(exp);
    const m = BigInt(mod);
    let result = 1n;
    
    // Handle negative base
    if (b < 0n) b += m;

    // Handle negative exponent (Modular Inverse)
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
    
    // If gcd != 1, no inverse
    if (old_r > 1n) throw new Error('Inverse does not exist');
    return (old_s % BigInt(m) + BigInt(m)) % BigInt(m);
}

export function verifyBlindMatch(pubKey, C_plat, C_blind_Str, proof) {
    const n = BigInt(pubKey.n.toString());
    const g = BigInt(pubKey.g.toString());
    const n2 = n * n;

    // Convert inputs to BigInt safely
    const C_p = BigInt(C_plat);
    const C_blind = BigInt(C_blind_Str);
    const A = BigInt(proof.A);
    const e = BigInt(proof.e);
    const z_alpha = BigInt(proof.z_alpha);
    const z_beta  = BigInt(proof.z_beta);
    const z_gamma = BigInt(proof.z_gamma);

    // 1. Recompute Challenge
    const e_check = generateChallenge(n, C_p, C_blind, A);
    
    if (e !== e_check) {
        console.error("Hash Mismatch: Integrity check failed.");
        return false;
    }

    // 2. Verify Equation
    // Check: C_plat^z_alpha * g^z_beta * z_gamma^N == A * C_blind^e
    
    // LHS Terms
    const lhs1 = modPow(C_p, z_alpha, n2);
    const lhs2 = modPow(g, z_beta, n2);      // Handles negative z_beta internally
    const lhs3 = modPow(z_gamma, n, n2);
    
    const LHS = (lhs1 * lhs2 * lhs3) % n2;

    // RHS Terms
    const rhs1 = A % n2;
    const rhs2 = modPow(C_blind, e, n2);
    
    const RHS = (rhs1 * rhs2) % n2;

    // Final Comparison
    if (LHS === RHS) {
        console.log("Proof Verified: Blind Calculation Correct.");
        return true;
    } else {
        console.error("Mathematical Verification Failed.");
        return false;
    }
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