const curve = require('./CurveGroup');
const BN = require('bn.js');

class Pedersen {
    /**
     * Compute a Pedersen commitment C = g^v * h^r
     * @param {BigInt|BN|number|string} value v (the value to commit to)
     * @param {BigInt|BN|string} r (the blinding factor)
     * @returns {Object} Elliptic curve point
     */
    static commit(value, r) {
        const vBN = new BN(value.toString());
        const rBN = new BN(r.toString(16), 16);

        const gV = curve.mul(curve.g, vBN);
        const hR = curve.mul(curve.h, rBN);

        return curve.add(gV, hR);
    }

    /**
     * Helper to generate a random blinding factor
     * @returns {BN} random scalar in Zq
     */
    static generateRandom() {
        return curve.getRandomScalar();
    }
}

module.exports = Pedersen;
