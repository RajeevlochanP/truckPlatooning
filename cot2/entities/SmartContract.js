const ZKP = require('../core/ZKP');

class SmartContract {
    constructor() {
        this.routeCommitments = new Map(); // id -> array of C_x
    }

    /**
     * Phase 1: Verify and log route commitments
     * @param {string} id - Identity of the participant
     * @param {Array<Object>} C_x_arr - Array of commitments
     * @param {Array<Object>} pi_init_arr - Array of Schnorr proofs
     * @returns {boolean}
     */
    verifyAndLogRoute(id, C_x_arr, pi_init_arr) {
        for (let i = 0; i < C_x_arr.length; i++) {
            const valid = ZKP.verifyInitProof(C_x_arr[i], pi_init_arr[i]);
            if (!valid) return false;
        }
        
        this.routeCommitments.set(id, C_x_arr);
        return true;
    }

    /**
     * Phase 2: Verify Bit-level and Linear Consistency Proofs (Batch Verification)
     * This acts as the public verification ledger mechanism.
     */
    verifyConsistencyBatch(id, B_matrix, pi_bit_matrix, pi_lin_arr) {
        const C_x_arr = this.routeCommitments.get(id);
        if (!C_x_arr) return false;
        
        for (let i = 0; i < C_x_arr.length; i++) {
            const B_arr = B_matrix[i];
            const pi_bits = pi_bit_matrix[i];
            
            // Verify Bit Proofs
            for (let j = 0; j < B_arr.length; j++) {
                if (!ZKP.verifyBitProof(B_arr[j], pi_bits[j])) {
                    return false;
                }
            }
            
            // Verify Linear Consistency
            if (!ZKP.verifyLinProof(C_x_arr[i], B_arr, pi_lin_arr[i])) {
                return false;
            }
        }
        return true;
    }
}

module.exports = SmartContract;
