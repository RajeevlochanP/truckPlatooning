const { modPow } = require('../crypto/paillier');

class SmartContract {
    constructor(pubA, pubL) {
        this.pubA = pubA;
        this.pubL = pubL;
    }

    verifyEvalProof(C_A, C_L, C_beta, C_blind, pi_eval) {
        const NA = this.pubA.N;
        const NA2 = this.pubA.N2;
        const gA = this.pubA.g;
        
        const NL = this.pubL.N;
        const NL2 = this.pubL.N2;
        const gL = this.pubL.g;
        
        const { A1, A2, A3, e, z_alpha, z_beta, z_1, z_2, z_3 } = pi_eval;
        
        // 1. (C_A)^(-z_alpha) * z_1^NA == A1 * C_beta^e (mod NA2)
        const lhs1 = (modPow(C_A, -z_alpha, NA2) * modPow(z_1, NA, NA2)) % NA2;
        const rhs1 = (A1 * modPow(C_beta, e, NA2)) % NA2;
        if (lhs1 !== rhs1) return false;
        
        // 2. g_A^(z_beta) * z_2^NA == A2 * C_beta^e (mod NA2)
        const lhs2 = (modPow(gA, z_beta, NA2) * modPow(z_2, NA, NA2)) % NA2;
        const rhs2 = (A2 * modPow(C_beta, e, NA2)) % NA2;
        if (lhs2 !== rhs2) return false;
        
        // 3. (C_L)^(z_alpha) * g_L^(z_beta) * z_3^NL == A3 * C_blind^e (mod NL2)
        const lhs3_1 = modPow(C_L, z_alpha, NL2);
        const lhs3_2 = modPow(gL, z_beta, NL2);
        const lhs3_3 = modPow(z_3, NL, NL2);
        const lhs3 = (((lhs3_1 * lhs3_2) % NL2) * lhs3_3) % NL2;
        const rhs3 = (A3 * modPow(C_blind, e, NL2)) % NL2;
        if (lhs3 !== rhs3) return false;
        
        return true;
    }
}

module.exports = SmartContract;
