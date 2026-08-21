const { modPow, randBigIntRange, modInverse } = require('../crypto/paillier');
const { sha256BigInt } = require('../crypto/nizkp');

class Leader {
    constructor(keys, pubA) {
        this.keys = keys;
        this.pubA = pubA;
    }

    commitWaypoint(w) {
        w = BigInt(w);
        const { N, N2, g } = this.keys.pub;
        
        const r_x = randBigIntRange(N - 1n) + 1n;
        const C_x = (modPow(g, w, N2) * modPow(r_x, N, N2)) % N2;

        const rho = randBigIntRange((1n << 128n) * N);
        const s = randBigIntRange(N - 1n) + 1n;

        const A_x = (modPow(g, rho, N2) * modPow(s, N, N2)) % N2;
        const e = sha256BigInt(N, g, C_x, A_x);

        const z_1 = rho + e * w;
        const z_2 = (s * modPow(r_x, e, N)) % N;

        const pi_init = { A_x, e, z_1, z_2 };
        return { C_x, r_x, pi_init, w };
    }
    
    decideMatch(C_blind) {
        const { N, N2, g } = this.keys.pub;
        const { lambda, mu, p, q } = this.keys.priv;
        
        const r_P = randBigIntRange(N - 1n) + 1n;
        const C_final = modPow(C_blind, r_P, N2);
        
        const L = (u) => (u - 1n) / N;
        const m_true = (L(modPow(C_final, lambda, N2)) * mu) % N;
        
        const isMatch = (m_true === 0n);
        
        const C_rand = (C_final * modPow(g, -m_true, N2)) % N2;
        
        const phiN = (p - 1n) * (q - 1n);
        const N_inv_phi = modInverse(N, phiN);
        const R = modPow(C_rand, N_inv_phi, N);
        
        const s = randBigIntRange(N2 / 2n);
        const A_L_prime = modPow(C_blind, s, N2);
        
        const e_L = sha256BigInt(N, C_blind, C_final, A_L_prime);
        const z_L = s + e_L * r_P;
        
        const pi_final = { m_true, R, C_final, A_L_prime, e_L, z_L };
        
        return { m_true, isMatch, pi_final };
    }
}

module.exports = Leader;
