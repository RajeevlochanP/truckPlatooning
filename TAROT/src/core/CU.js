const { encryptBit, decryptBit } = require('../crypto/gm');

class CU {
    /**
     * Converts a 32-bit integer into an array of 32 bits (0s and 1s).
     */
    static numberTo32Bits(num) {
        const bits = [];
        for (let i = 0; i < 32; i++) {
            bits.push((num >>> i) & 1);
        }
        return bits;
    }

    /**
     * Phase 1: Encryptions (OFFLINE SETUP)
     * Encrypts each of the 32 bits of a waypoint.
     */
    static encryptWaypoint(waypoint, pk) {
        const bits = this.numberTo32Bits(waypoint);
        return bits.map(bit => encryptBit(bit, pk));
    }

    /**
     * Phase 2: Homomorphic Evaluation (ONLINE MATCHING by CU_j)
     * Computes the Hadamard product of two encrypted waypoints and randomly shuffles the result.
     */
    static evaluateEquality(encA, encB, n) {
        const E = new Array(32);
        for (let k = 0; k < 32; k++) {
            E[k] = (encA[k] * encB[k]) % n;
        }

        // Randomly shuffle the 32 ciphertexts to hide positional bit leakage
        for (let i = E.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [E[i], E[j]] = [E[j], E[i]];
        }
        return E;
    }

    /**
     * Phase 3: Decryption & Decision (ONLINE MATCHING by CU_i)
     * Decrypts the array of ciphertexts. Short-circuits if any decrypted bit is 1.
     */
    static decryptAndDecide(E, sk) {
        for (let k = 0; k < 32; k++) {
            const bit = decryptBit(E[k], sk);
            if (bit === 1) {
                return false; // A != B
            }
        }
        return true; // A == B
    }
}

module.exports = CU;
