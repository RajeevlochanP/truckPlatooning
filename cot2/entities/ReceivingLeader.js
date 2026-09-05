const crypto = require('crypto');
const Pedersen = require('../core/Pedersen');
const ZKP = require('../core/ZKP');
const GarbledCircuit = require('../core/GarbledCircuit');
const OTExtension = require('../core/OTExtension');

class ReceivingLeader {
    constructor(id) {
        this.id = id;
        this.sigma = 32;
        this.otExt = new OTExtension();
        this.gc = new GarbledCircuit(this.sigma);
    }

    /**
     * Phase 1: On-Chain Route Commitment
     */
    commitRoute(route) {
        this.l = route.length;
        this.route = route;
        this.C_x_arr = [];
        this.pi_init_arr = [];
        this.bitsMatrix = []; // b_L,i,j

        for (let i = 0; i < this.l; i++) {
            const w = this.route[i];
            const r = Pedersen.generateRandom();
            const C = Pedersen.commit(w, r);
            this.C_x_arr.push(C);
            
            const pi_init = ZKP.generateInitProof(w, r, C);
            this.pi_init_arr.push(pi_init);

            const rowBits = [];
            for (let j = 0; j < this.sigma; j++) {
                rowBits.push(Number((BigInt(w) >> BigInt(j)) & 1n));
            }
            this.bitsMatrix.push(rowBits);
        }

        return { C_x_arr: this.C_x_arr, pi_init_arr: this.pi_init_arr };
    }

    /**
     * Phase 3: Exact Prefix Circuit Garbling
     */
    garbleCircuit() {
        const gcOut = this.gc.garble(this.l, this.bitsMatrix);
        
        this.delta = gcOut.delta;
        this.applicantLabels = gcOut.applicantLabels; // W_A^0
        this.leaderLabels = gcOut.leaderLabels; // W_L^0
        this.tables = gcOut.tables;
        this.pOutputs = gcOut.pOutputs; // W_P^0
        this.publicDecodingTable = gcOut.outputDecoding;

        // Leader knows their own bits, so they prepare their active labels to send to A
        this.activeLeaderLabels = [];
        for (let i = 0; i < this.l; i++) {
            const row = [];
            for (let j = 0; j < this.sigma; j++) {
                if (this.bitsMatrix[i][j] === 0) {
                    row.push(this.leaderLabels[i][j]);
                } else {
                    // W^1 = W^0 ^ delta
                    const w1 = Buffer.alloc(16);
                    for(let k=0; k<16; k++) w1[k] = this.leaderLabels[i][j][k] ^ this.delta[k];
                    row.push(w1);
                }
            }
            this.activeLeaderLabels.push(row);
        }

        return {
            tables: this.tables,
            publicDecodingTable: this.publicDecodingTable,
            activeLeaderLabels: this.activeLeaderLabels
        };
    }

    /**
     * Phase 4: Sender OT encryption
     */
    generateOTSenderResponse(U_matrix) {
        // Base OT choices (simulated)
        this.baseChoiceBits = crypto.randomBytes(16);
        
        // Prepare wire pairs for Applicant's inputs
        const wirePairs = [];
        for (let i = 0; i < this.l; i++) {
            for (let j = 0; j < this.sigma; j++) {
                const w0 = this.applicantLabels[i][j];
                const w1 = Buffer.alloc(16);
                for(let k=0; k<16; k++) w1[k] = w0[k] ^ this.delta[k];
                wirePairs.push({ w0, w1 });
            }
        }

        const payloads = this.otExt.senderEncrypt(U_matrix, this.baseChoiceBits, wirePairs);
        return payloads;
    }

    /**
     * Phase 5: Mutual Output Verification
     */
    verifyAndDeriveSessionKey(k_star, pi_eval, Y_A, C_A_arr) {
        // Verify pi_eval == H_expected
        const h = crypto.createHash('sha256');
        
        for (let i = 0; i < this.l; i++) {
            if (i < k_star) {
                // Should be W_P_i^1
                const w1 = Buffer.alloc(16);
                for(let k=0; k<16; k++) w1[k] = this.pOutputs[i][k] ^ this.delta[k];
                h.update(w1);
            } else {
                // Should be W_P_i^0
                h.update(this.pOutputs[i]);
            }
        }
        
        const H_expected = h.digest().toString('hex');
        
        if (pi_eval !== H_expected) {
            return { success: false, error: "pi_eval mismatch. Output proof invalid." };
        }

        // Ephemeral DH
        if (Y_A) {
            this.x_L = crypto.randomBytes(32);
            const ecdh = crypto.createECDH('secp256k1');
            ecdh.setPrivateKey(this.x_L);
            const Y_L = ecdh.getPublicKey('hex');
            
            const sharedSecret = ecdh.computeSecret(Buffer.from(Y_A, 'hex'));
            const K_DH = crypto.createHash('sha256').update(sharedSecret).digest();
            
            const kdf = crypto.createHash('sha256');
            kdf.update(K_DH);
            kdf.update(Buffer.from([k_star]));
            
            for(let C of C_A_arr) kdf.update(C.encode('hex', true));
            for(let C of this.C_x_arr) kdf.update(C.encode('hex', true));
            
            this.K_Branch = kdf.digest();
            return { success: true, Y_L, K_Branch: this.K_Branch };
        }

        return { success: true }; // Protocol valid, but k_star < tau_min so no DH
    }
}

module.exports = ReceivingLeader;
