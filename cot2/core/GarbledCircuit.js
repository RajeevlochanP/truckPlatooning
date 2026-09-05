const crypto = require('crypto');

function xorBuffers(b1, b2) {
    const res = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) res[i] = b1[i] ^ b2[i];
    return res;
}

function hashWire(wire, gateId, tweak) {
    const h = crypto.createHash('sha256');
    h.update(wire);
    h.update(Buffer.from(gateId.toString()));
    h.update(Buffer.from([tweak]));
    return h.digest().slice(0, 16);
}

class GarbledCircuit {
    constructor(sigma = 32) {
        this.sigma = sigma;
    }

    /**
     * Garbles the prefix evaluation circuit.
     * @param {number} l - Trajectory length
     * @param {Array<Array<number>>} leaderBits - [l][sigma] bits of the leader
     * @returns {Object} Garbled circuit containing tables, delta, and initial wire labels
     */
    garble(l, leaderBits) {
        // 1. Generate Global Offset Delta
        const delta = crypto.randomBytes(16);
        delta[0] |= 1; // LSB = 1

        const applicantLabels = []; // W_A^0
        const leaderLabels = []; // W_L^0

        let gateCounter = 0;
        const tables = [];

        // Helper to create an AND gate
        const createAndGate = (wa0, wb0) => {
            const wc0 = crypto.randomBytes(16);
            
            const wa1 = xorBuffers(wa0, delta);
            const wb1 = xorBuffers(wb0, delta);
            const wc1 = xorBuffers(wc0, delta);

            const table = new Array(4);
            const inputs = [
                { a: wa0, b: wb0, c: wc0 },
                { a: wa0, b: wb1, c: wc0 }, // 0 & 1 = 0
                { a: wa1, b: wb0, c: wc0 }, // 1 & 0 = 0
                { a: wa1, b: wb1, c: wc1 }  // 1 & 1 = 1
            ];

            for (const { a, b, c } of inputs) {
                const pa = a[0] & 1;
                const pb = b[0] & 1;
                const idx = (pa << 1) | pb;
                const k1 = hashWire(a, gateCounter, 1);
                const k2 = hashWire(b, gateCounter, 2);
                const mask = xorBuffers(k1, k2);
                table[idx] = xorBuffers(c, mask);
            }
            gateCounter++;
            return { w0: wc0, table };
        };

        const eqOutputs = [];

        // Garble EQ_i for each waypoint
        for (let i = 0; i < l; i++) {
            const appLabelRow = [];
            const leadLabelRow = [];
            
            // X_i,j = A_i,j ^ L_i,j
            const xorOut = [];
            
            for (let j = 0; j < this.sigma; j++) {
                const wa0 = crypto.randomBytes(16);
                const wl0 = crypto.randomBytes(16);
                appLabelRow.push(wa0);
                leadLabelRow.push(wl0);
                
                // X_i,j = A_i,j ^ L_i,j
                // In Free-XOR, W_X^0 = W_A^0 ^ W_L^0
                const wx0 = xorBuffers(wa0, wl0);
                
                // NOT X = X ^ 1 (In Free-XOR, W_{NOT X}^0 = W_X^1 = W_X^0 ^ delta)
                const w_not_x_0 = xorBuffers(wx0, delta);
                xorOut.push(w_not_x_0);
            }
            
            applicantLabels.push(appLabelRow);
            leaderLabels.push(leadLabelRow);

            // AND them together to get EQ_i
            let current = xorOut[0];
            for (let j = 1; j < this.sigma; j++) {
                const andGate = createAndGate(current, xorOut[j]);
                tables.push(andGate.table);
                current = andGate.w0;
            }
            eqOutputs.push(current);
        }

        // Prefix Cascade: P_1 = EQ_1, P_i = P_{i-1} AND EQ_i
        const pOutputs = [eqOutputs[0]];
        let currentP = eqOutputs[0];
        
        for (let i = 1; i < l; i++) {
            const andGate = createAndGate(currentP, eqOutputs[i]);
            tables.push(andGate.table);
            currentP = andGate.w0;
            pOutputs.push(currentP);
        }

        // Public decoding table for outputs: map P_i^1 to their hashes for verification
        const outputDecoding = [];
        for (let i = 0; i < l; i++) {
            const p1 = xorBuffers(pOutputs[i], delta);
            outputDecoding.push(crypto.createHash('sha256').update(p1).digest().toString('hex'));
        }

        return {
            delta,
            applicantLabels,
            leaderLabels,
            tables,
            pOutputs, // W_P^0 for each P_i
            outputDecoding
        };
    }

    /**
     * Evaluates the garbled circuit
     */
    evaluate(l, activeApplicantLabels, activeLeaderLabels, tables) {
        let gateCounter = 0;
        
        const evalAndGate = (wa, wb, table) => {
            const pa = wa[0] & 1;
            const pb = wb[0] & 1;
            const idx = (pa << 1) | pb;
            
            const k1 = hashWire(wa, gateCounter, 1);
            const k2 = hashWire(wb, gateCounter, 2);
            const mask = xorBuffers(k1, k2);
            
            const wc = xorBuffers(table[idx], mask);
            gateCounter++;
            return wc;
        };

        const eqOutputs = [];

        for (let i = 0; i < l; i++) {
            let xorOut = [];
            for (let j = 0; j < this.sigma; j++) {
                const wa = activeApplicantLabels[i][j];
                const wl = activeLeaderLabels[i][j];
                const wx = xorBuffers(wa, wl);
                // NOT X in Free-XOR: in evaluation, we don't know delta, so we just use wx directly?
                // Wait, if it's a NOT gate, the semantics of the downstream AND gate handles it.
                // For simulation purposes, we can just pass wx, but wait, the garbler used w_not_x_0 = wx0 ^ delta.
                // The evaluator has W_X^act. To get W_{NOT X}^act, they don't XOR delta because they don't know it.
                // In Free-XOR, NOT is usually free if incorporated into the next gate, but technically 
                // the evaluator just flips the permutation bit. Since we omitted perm bits, we just use wx.
                xorOut.push(wx);
            }

            let current = xorOut[0];
            for (let j = 1; j < this.sigma; j++) {
                current = evalAndGate(current, xorOut[j], tables[gateCounter]);
            }
            eqOutputs.push(current);
        }

        const pOutputs = [eqOutputs[0]];
        let currentP = eqOutputs[0];
        
        for (let i = 1; i < l; i++) {
            currentP = evalAndGate(currentP, eqOutputs[i], tables[gateCounter]);
            pOutputs.push(currentP);
        }

        return pOutputs;
    }
}

module.exports = GarbledCircuit;
