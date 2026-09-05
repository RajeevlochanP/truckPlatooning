const crypto = require('crypto');
const Pedersen = require('../core/Pedersen');
const ZKP = require('../core/ZKP');
const GarbledCircuit = require('../core/GarbledCircuit');
const OTExtension = require('../core/OTExtension');

class ApplicantLeader {
    constructor(id) {
        this.id = id;
        this.sigma = 32; // 32-bit waypoints
        this.otExt = new OTExtension();
        this.gc = new GarbledCircuit(this.sigma);
    }

    /**
     * Phase 1: On-Chain Route Commitment
     */
    commitRoute(route) {
        this.l = route.length;
        this.route = route;
        this.r_arr = [];
        this.C_x_arr = [];
        this.pi_init_arr = [];

        for (let i = 0; i < this.l; i++) {
            const w = this.route[i];
            const r = Pedersen.generateRandom();
            this.r_arr.push(r);

            const C = Pedersen.commit(w, r);
            this.C_x_arr.push(C);

            const pi_init = ZKP.generateInitProof(w, r, C);
            this.pi_init_arr.push(pi_init);
        }

        return { C_x_arr: this.C_x_arr, pi_init_arr: this.pi_init_arr };
    }

    /**
     * Phase 2: Bit-Level Commitments & Consistency Proofs
     */
    generateBitCommitments() {
        this.B_matrix = [];
        this.pi_bit_matrix = [];
        this.pi_lin_arr = [];
        this.s_matrix = [];
        this.flatBits = [];

        for (let i = 0; i < this.l; i++) {
            const w = BigInt(this.route[i]);
            const B_arr = [];
            const pi_bits = [];
            const s_arr = [];

            for (let j = 0; j < this.sigma; j++) {
                const b = Number((w >> BigInt(j)) & 1n);
                this.flatBits.push(b);
                
                const s = Pedersen.generateRandom();
                s_arr.push(s);

                const B = Pedersen.commit(b, s);
                B_arr.push(B);

                const pi_bit = ZKP.generateBitProof(b, s, B);
                pi_bits.push(pi_bit);
            }

            this.B_matrix.push(B_arr);
            this.s_matrix.push(s_arr);
            this.pi_bit_matrix.push(pi_bits);

            const pi_lin = ZKP.generateLinProof(this.C_x_arr[i], B_arr, s_arr, this.r_arr[i]);
            this.pi_lin_arr.push(pi_lin);
        }

        return {
            B_matrix: this.B_matrix,
            pi_bit_matrix: this.pi_bit_matrix,
            pi_lin_arr: this.pi_lin_arr
        };
    }

    /**
     * Phase 4: Receiver OT setup (Generate U matrix)
     */
    generateOTReceiverRequest() {
        const { T_cols, U_matrix } = this.otExt.receiverDeriveU(this.flatBits);
        this.T_cols = T_cols;
        return U_matrix;
    }

    /**
     * Phase 4: Receiver decrypt active labels
     */
    receiveOTPayloads(payloads) {
        this.activeApplicantLabelsFlat = this.otExt.receiverDecrypt(this.T_cols, this.flatBits, payloads);
        
        // Reshape to l x sigma
        this.activeApplicantLabels = [];
        let idx = 0;
        for (let i = 0; i < this.l; i++) {
            const row = [];
            for (let j = 0; j < this.sigma; j++) {
                row.push(this.activeApplicantLabelsFlat[idx++]);
            }
            this.activeApplicantLabels.push(row);
        }
    }

    /**
     * Phase 5: Circuit Evaluation & Mutual Verification
     */
    evaluateAndProve(activeLeaderLabels, gcTables, publicDecodingTable, tau_min) {
        // activeLeaderLabels are passed directly from leader for this protocol
        // In a real network, Leader sends exactly one label per bit based on their own route
        
        const pOutputs = this.gc.evaluate(this.l, this.activeApplicantLabels, activeLeaderLabels, gcTables);
        
        let k_star = 0;
        for (let i = 0; i < this.l; i++) {
            const p1Hash = crypto.createHash('sha256').update(pOutputs[i]).digest().toString('hex');
            // If the output label matches the decoding table's hash for P_i^1, then it's a match
            if (p1Hash === publicDecodingTable[i]) {
                k_star++;
            } else {
                break; // contiguous prefix broken
            }
        }

        // Generate pi_eval
        const h = crypto.createHash('sha256');
        for (let i = 0; i < this.l; i++) {
            h.update(pOutputs[i]);
        }
        const pi_eval = h.digest().toString('hex');

        // Ephemeral DH for Key Derivation if condition met
        let Y_A = null;
        if (k_star >= tau_min) {
            // Generate ephemeral key
            this.x_A = crypto.randomBytes(32);
            // In a real implementation we use the CurveGroup, but using crypto ECDH is easier for session keys
            const ecdh = crypto.createECDH('secp256k1');
            ecdh.setPrivateKey(this.x_A);
            Y_A = ecdh.getPublicKey('hex');
            this.ecdh = ecdh;
        }

        return { k_star, pi_eval, Y_A };
    }

    deriveSessionKey(Y_L, k_star, C_L_arr) {
        const sharedSecret = this.ecdh.computeSecret(Buffer.from(Y_L, 'hex'));
        const K_DH = crypto.createHash('sha256').update(sharedSecret).digest();
        
        const kdf = crypto.createHash('sha256');
        kdf.update(K_DH);
        kdf.update(Buffer.from([k_star]));
        
        for(let C of this.C_x_arr) kdf.update(C.encode('hex', true));
        for(let C of C_L_arr) kdf.update(C.encode('hex', true));
        
        this.K_Branch = kdf.digest();
        return this.K_Branch;
    }
}

module.exports = ApplicantLeader;
