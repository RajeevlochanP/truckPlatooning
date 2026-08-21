const { modPow, randBigIntRange } = require('../crypto/paillier');
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

        const maxRho = (1n << 128n) * N;
        const rho = randBigIntRange(maxRho);
        
        let s;
        do { s = randBigIntRange(N); } while (s === 0n);

        const A_x = (modPow(g, rho, N2) * modPow(s, N, N2)) % N2;

        const e = sha256BigInt(N, g, C_x, A_x);

        const z_1 = rho + e * w;
        const z_2 = (s * modPow(r_x, e, N)) % N;

        const pi_init = { A_x, e, z_1, z_2 };
        return { C_x, r_x, pi_init, w };
    }
    
    // Algorithm 2: Cross-Modulus Path Evaluation
    evaluateMatch(w_A, C_A, r_A, C_L) {
        w_A = BigInt(w_A);
        const NA = this.keys.pub.N;
        const NA2 = this.keys.pub.N2;
        const gA = this.keys.pub.g;
        
        const NL = this.pubL.N;
        const NL2 = this.pubL.N2;
        const gL = this.pubL.g;
        
        const alpha = randBigIntRange(NA - 1n) + 1n; 
        const beta = -w_A * alpha;
        
        const r_u = randBigIntRange(NA - 1n) + 1n;
        const gamma = randBigIntRange(NL - 1n) + 1n;
        
        const C_beta = (modPow(C_A, -alpha, NA2) * modPow(r_u, NA, NA2)) % NA2;
        
        const part1 = modPow(C_L, alpha, NL2);
        const part2 = modPow(gL, beta, NL2);
        const part3 = modPow(gamma, NL, NL2);
        const C_blind = (((part1 * part2) % NL2) * part3) % NL2;
        
        const r_v = (modPow(r_A, -alpha, NA) * r_u) % NA;
        
        const r_alpha = randBigIntRange((1n << 128n) * NA * NL);
        const r_beta = randBigIntRange((1n << 128n) * NA);
        const r_s1 = randBigIntRange(NA - 1n) + 1n;
        const r_s2 = randBigIntRange(NA - 1n) + 1n;
        const r_s3 = randBigIntRange(NL - 1n) + 1n;
        
        const A1 = (modPow(C_A, -r_alpha, NA2) * modPow(r_s1, NA, NA2)) % NA2;
        const A2 = (modPow(gA, r_beta, NA2) * modPow(r_s2, NA, NA2)) % NA2;
        
        const A3_p1 = modPow(C_L, r_alpha, NL2);
        const A3_p2 = modPow(gL, r_beta, NL2);
        const A3_p3 = modPow(r_s3, NL, NL2);
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
