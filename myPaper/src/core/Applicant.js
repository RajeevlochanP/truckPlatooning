const { modPow, randBigIntRange, modInverse } = require('../crypto/paillier');
const { sha256BigInt } = require('../crypto/nizkp');

class Applicant {
    constructor(keys, pubL) {
        this.keys = keys;
        this.pubL = pubL;
    }

    // Algorithm 1: Universal Route Commitment
    commitWaypoint(w) {
        w = BigInt(w);
        const { N, N2, g } = this.keys.pub;
        
        let r_x;
        do { r_x = randBigIntRange(N); } while (r_x === 0n);
        
        const C_x = (modPow(g, w, N2) * modPow(r_x, N, N2)) % N2;

        const rho = randBigIntRange(1n << 464n);
        
        let s;
        do { s = randBigIntRange(N); } while (s === 0n);

        const A_x = (modPow(g, rho, N2) * modPow(s, N, N2)) % N2;

        const e = sha256BigInt(N, g, C_x, A_x);

        const z_1 = rho + e * w;
        const z_2 = (s * modPow(r_x, e, N)) % N;

        const C_A_inv = modInverse(C_x, N2);
        const r_A_inv = modInverse(r_x, N);

        const pi_init = { A_x, e, z_1, z_2 };
        return { C_x, r_x, pi_init, w, C_A_inv, r_A_inv };
    }
    
    precomputeEval(C_A_inv) {
        const NA = this.keys.pub.N;
        const NA2 = this.keys.pub.N2;
        const gA = this.keys.pub.g;
        
        const NL = this.pubL.N;
        const NL2 = this.pubL.N2;
        
        const alpha = randBigIntRange(1n << 128n); 
        const r_u = randBigIntRange(NA - 1n) + 1n;
        const gamma = randBigIntRange(1n << 128n);
        
        const r_alpha = randBigIntRange(1n << 464n);
        const r_beta = randBigIntRange(1n << 464n);
        const r_s1 = randBigIntRange(NA - 1n) + 1n;
        const r_s2 = randBigIntRange(NA - 1n) + 1n;
        const r_s3 = randBigIntRange(NL - 1n) + 1n;
        
        const r_u_N = modPow(r_u, NA, NA2);
        const gamma_N = modPow(gamma, NL, NL2);
        const r_s3_N = modPow(r_s3, NL, NL2);
        
        const A1 = (modPow(C_A_inv, r_alpha, NA2) * modPow(r_s1, NA, NA2)) % NA2;
        const gA_r_beta = (1n + (r_beta % NA) * NA) % NA2;
        const A2 = (gA_r_beta * modPow(r_s2, NA, NA2)) % NA2;
        
        return { alpha, r_u, gamma, r_alpha, r_beta, r_s1, r_s2, r_s3, A1, A2, r_u_N, gamma_N, r_s3_N };
    }

    // Algorithm 2: Cross-Modulus Path Evaluation
    evaluateMatch(w_A, C_A, C_A_inv, r_A_inv, C_L, state) {
        w_A = BigInt(w_A);
        const NA = this.keys.pub.N;
        const NA2 = this.keys.pub.N2;
        
        const NL = this.pubL.N;
        const NL2 = this.pubL.N2;
        const gL = this.pubL.g;
        
        const { alpha, r_u, gamma, r_alpha, r_beta, r_s1, r_s2, r_s3, A1, A2, r_u_N, gamma_N, r_s3_N } = state;
        const beta = -w_A * alpha;
        
        const C_beta = (modPow(C_A_inv, alpha, NA2) * r_u_N) % NA2;
        
        const part1 = modPow(C_L, alpha, NL2);
        const part2 = ((1n + ((beta % NL + NL) % NL) * NL) % NL2 + NL2) % NL2;
        const part3 = gamma_N;
        const C_blind = (((part1 * part2) % NL2) * part3) % NL2;
        
        const r_v = (modPow(r_A_inv, alpha, NA) * r_u) % NA;
        
        const A3_p1 = modPow(C_L, r_alpha, NL2);
        const A3_p2 = (1n + (r_beta % NL) * NL) % NL2;
        const A3_p3 = r_s3_N;
        const A3 = (((A3_p1 * A3_p2) % NL2) * A3_p3) % NL2;
        
        const e = sha256BigInt(C_A, C_L, C_beta, C_blind, A1, A2, A3);
        
        const z_alpha = r_alpha + e * alpha;
        const z_beta = r_beta + e * beta;
        
        const z_1 = (r_s1 * modPow(r_u, e, NA)) % NA;
        const z_2 = (r_s2 * modPow(r_v, e, NA)) % NA;
        const z_3 = (r_s3 * modPow(gamma, e, NL)) % NL;
        
        const pi_eval = { A1, A2, A3, e, z_alpha, z_beta, z_1, z_2, z_3 };
        
        return { C_beta, C_blind, pi_eval };
    }
}

module.exports = Applicant;
