const { modPow } = require('../crypto/paillier');
const crypto = require('crypto');

class SmartContract {
    constructor(pubA, pubL) {
        this.pubA = pubA;
        this.pubL = pubL;
    }

    verifyEvalProof(C_A, C_L, C_beta, C_blind, pi_eval) {
        const NA = this.pubA.N;
        const NA2 = this.pubA.N2;
        
        const NL = this.pubL.N;
        const NL2 = this.pubL.N2;
        
        const { A1, A2, A3, e, z_alpha, z_beta, z_1, z_2, z_3 } = pi_eval;
        
        // 1. z_1^NA == A1 * C_beta^e * C_A^{z_alpha} (mod NA2)
        const lhs1 = modPow(z_1, NA, NA2);
        const rhs1_part1 = (A1 * modPow(C_beta, e, NA2)) % NA2;
        const rhs1_part2 = modPow(C_A, z_alpha, NA2);
        const rhs1 = (rhs1_part1 * rhs1_part2) % NA2;
        if (lhs1 !== rhs1) return false;
        
        // 2. g_A^(z_beta) * z_2^NA == A2 * C_beta^e (mod NA2)
        const gA_z_beta = ((1n + ((z_beta % NA + NA) % NA) * NA) % NA2 + NA2) % NA2;
        const lhs2 = (gA_z_beta * modPow(z_2, NA, NA2)) % NA2;
        const rhs2 = (A2 * modPow(C_beta, e, NA2)) % NA2;
        if (lhs2 !== rhs2) return false;
        
        // 3. (C_L)^(z_alpha) * g_L^(z_beta) * z_3^NL == A3 * C_blind^e (mod NL2)
        const lhs3_1 = modPow(C_L, z_alpha, NL2);
        const gL_z_beta = ((1n + ((z_beta % NL + NL) % NL) * NL) % NL2 + NL2) % NL2;
        const lhs3_3 = modPow(z_3, NL, NL2);
        const lhs3 = (((lhs3_1 * gL_z_beta) % NL2) * lhs3_3) % NL2;
        const rhs3 = (A3 * modPow(C_blind, e, NL2)) % NL2;
        if (lhs3 !== rhs3) return false;
        
        return true;
    }

    verifyEvalProofBatch(C_A_arr, C_L_arr, C_beta_arr, C_blind_arr, pi_eval_arr) {
        const NA = this.pubA.N;
        const NA2 = this.pubA.N2;
        
        const NL = this.pubL.N;
        const NL2 = this.pubL.N2;
        
        const l = pi_eval_arr.length;
        if (l === 0) return true;

        const seed = crypto.createHash('sha256').update(pi_eval_arr.map(p => p.A1).join('')).digest('hex');

        let baseAcc1 = 1n;
        let baseAcc2 = 1n;
        let baseAcc3 = 1n;

        let rhs1_prod = 1n;

        let z_beta_sum_NA = 0n;
        let lhs2_rhs_prod = 1n;

        let lhs3_CL_prod = 1n;
        let rhs3_prod = 1n;
        let z_beta_sum_NL = 0n;

        for (let i = 0; i < l; i++) {
            const pi = pi_eval_arr[i];
            const rho = BigInt('0x' + seed.slice((i * 4) % 56, (i * 4) % 56 + 4)) + 1n;
            
            // Base Accumulators for N-th powers
            baseAcc1 = (baseAcc1 * modPow(pi.z_1, rho, NA)) % NA;
            baseAcc2 = (baseAcc2 * modPow(pi.z_2, rho, NA)) % NA;
            baseAcc3 = (baseAcc3 * modPow(pi.z_3, rho, NL)) % NL;

            // Common terms
            const cBeta_part = modPow(C_beta_arr[i], pi.e * rho, NA2);

            // Eq 1
            const a1_part = modPow(pi.A1, rho, NA2);
            const cA_part = modPow(C_A_arr[i], pi.z_alpha * rho, NA2);
            const rhs1_term = (((a1_part * cBeta_part) % NA2) * cA_part) % NA2;
            rhs1_prod = (rhs1_prod * rhs1_term) % NA2;

            // Eq 2
            z_beta_sum_NA = (z_beta_sum_NA + pi.z_beta * rho) % NA;
            const a2_part = modPow(pi.A2, rho, NA2);
            lhs2_rhs_prod = (lhs2_rhs_prod * ((a2_part * cBeta_part) % NA2)) % NA2;

            // Eq 3
            const cL_part = modPow(C_L_arr[i], pi.z_alpha * rho, NL2);
            lhs3_CL_prod = (lhs3_CL_prod * cL_part) % NL2;
            z_beta_sum_NL = (z_beta_sum_NL + pi.z_beta * rho) % NL;
            
            const a3_part = modPow(pi.A3, rho, NL2);
            const cBlind_part = modPow(C_blind_arr[i], pi.e * rho, NL2);
            rhs3_prod = (rhs3_prod * ((a3_part * cBlind_part) % NL2)) % NL2;
        }

        const totalAcc1 = modPow(baseAcc1, NA, NA2);
        const totalAcc2 = modPow(baseAcc2, NA, NA2);
        const totalAcc3 = modPow(baseAcc3, NL, NL2);

        // Check Eq 1
        if (totalAcc1 !== rhs1_prod) return false;

        // Check Eq 2
        const gA_z_beta_sum = ((1n + ((z_beta_sum_NA % NA + NA) % NA) * NA) % NA2 + NA2) % NA2;
        const lhs2 = (gA_z_beta_sum * totalAcc2) % NA2;
        if (lhs2 !== lhs2_rhs_prod) return false;

        // Check Eq 3
        const gL_z_beta_sum = ((1n + ((z_beta_sum_NL % NL + NL) % NL) * NL) % NL2 + NL2) % NL2;
        const lhs3 = (((lhs3_CL_prod * gL_z_beta_sum) % NL2) * totalAcc3) % NL2;
        if (lhs3 !== rhs3_prod) return false;

        return true;
    }

    verifyFinalProof(C_blind, pi_final, pubL) {
        const N = pubL.N;
        const N2 = pubL.N2;
        
        const { m_true, R, C_final, A_L_prime, e_L, z_L } = pi_final;
        
        // 1. Verify Double-Blinding ZKP:
        // C_blind^{z_L} == A_L' * C_final^{e_L} (mod N^2)
        const lhs1 = modPow(C_blind, z_L, N2);
        const rhs1 = (A_L_prime * modPow(C_final, e_L, N2)) % N2;
        if (lhs1 !== rhs1) return false;
        
        // 2. Verify Deterministic Decryption:
        // R^N * g^{m_true} == C_final (mod N^2)
        // Optimization: g^{m_true} mod N^2 == (1 + m_true * N) mod N^2
        const lhs2_part1 = modPow(R, N, N2);
        const lhs2_part2 = (1n + m_true * N) % N2;
        const lhs2 = (lhs2_part1 * lhs2_part2) % N2;
        
        if (lhs2 !== C_final) return false;
        
        return true;
    }

    verifyFinalProofBatch(C_blind_arr, pi_final_arr, pubL) {
        const N = pubL.N;
        const N2 = pubL.N2;
        const l = pi_final_arr.length;
        if (l === 0) return true;
        
        const seed = crypto.createHash('sha256').update(
            pi_final_arr.map(p => p.A_L_prime.toString()).join(':')
        ).digest();
        
        const rhos = [];
        for (let i = 0; i < l; i++) {
            rhos.push(BigInt('0x' + crypto.createHash('sha256').update(seed.toString('hex') + i).digest('hex').slice(0, 16)) + 1n);
        }
        
        let lhs1_prod = 1n;
        let rhs1_prod = 1n;
        
        let r_prod_N = 1n;
        let m_true_sum = 0n;
        let c_final_prod = 1n;
        
        for (let i = 0; i < l; i++) {
            const pi = pi_final_arr[i];
            const rho = rhos[i];
            
            // 1. Verify Double-Blinding ZKP:
            lhs1_prod = (lhs1_prod * modPow(C_blind_arr[i], pi.z_L * rho, N2)) % N2;
            
            const aL_part = modPow(pi.A_L_prime, rho, N2);
            const cFinal_part = modPow(pi.C_final, pi.e_L * rho, N2);
            rhs1_prod = (rhs1_prod * ((aL_part * cFinal_part) % N2)) % N2;
            
            // 2. Verify Deterministic Decryption:
            r_prod_N = (r_prod_N * modPow(pi.R, rho, N)) % N;
            m_true_sum = (m_true_sum + pi.m_true * rho) % N;
            
            c_final_prod = (c_final_prod * modPow(pi.C_final, rho, N2)) % N2;
        }
        
        if (lhs1_prod !== rhs1_prod) return false;
        
        const r_total_N = modPow(r_prod_N, N, N2);
        const g_m_true_sum = ((1n + ((m_true_sum % N + N) % N) * N) % N2 + N2) % N2;
        const lhs2 = (r_total_N * g_m_true_sum) % N2;
        
        if (lhs2 !== c_final_prod) return false;
        
        return true;
    }
}

module.exports = SmartContract;
