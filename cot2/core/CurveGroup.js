const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const crypto = require('crypto');
const BN = require('bn.js');

// Helper to compute modular square root for p = 3 mod 4
// secp256k1 prime p = 2^256 - 2^32 - 977 (which is 3 mod 4)
// So sqrt(a) = a^((p+1)/4) mod p
function modSqrt(a, p) {
    let pPlus1 = p.add(new BN(1));
    let exponent = pPlus1.div(new BN(4));
    return a.redPow(exponent);
}

function hashToCurve(generatorPoint) {
    const p = ec.curve.p;
    let counter = 0;
    
    // Convert generator point to buffer
    const gBuf = Buffer.from(generatorPoint.encode('hex', false), 'hex');
    
    while (true) {
        // Hash the generator along with a counter
        const hash = crypto.createHash('sha256');
        hash.update(gBuf);
        hash.update(Buffer.from(counter.toString()));
        const xBuf = hash.digest();
        
        let x = new BN(xBuf);
        // Ensure x is less than p
        if (x.cmp(p) >= 0) {
            counter++;
            continue;
        }

        // Check if x^3 + 7 is a quadratic residue mod p
        // Equation of secp256k1: y^2 = x^3 + 7
        const redCtx = BN.red(p);
        const xRed = x.toRed(redCtx);
        const y2 = xRed.redPow(new BN(3)).redAdd(new BN(7).toRed(redCtx));
        
        // Check Euler's criterion: y2^((p-1)/2) == 1 mod p
        const pMinus1Over2 = p.sub(new BN(1)).div(new BN(2));
        const check = y2.redPow(pMinus1Over2);
        
        if (check.fromRed().cmp(new BN(1)) === 0) {
            // It is a quadratic residue, calculate y
            const yRed = modSqrt(y2, p);
            const y = yRed.fromRed();
            
            // Create and return the point
            const point = ec.curve.point(x, y);
            // Verify point is on curve
            if (ec.curve.validate(point)) {
                return point;
            }
        }
        counter++;
    }
}

class CurveGroup {
    constructor() {
        this.ec = ec;
        this.n = ec.curve.n; // Order of the curve group
        this.p = ec.curve.p; // Prime field
        this.g = ec.g;
        this.h = hashToCurve(this.g);
    }

    // Scalar multiplication: point * scalar
    mul(point, scalar) {
        // elliptic handles BigInt/BN wrapping mostly, but BN is safest
        let s = new BN(scalar.toString(16), 16);
        // Ensure scalar is mod n
        s = s.umod(this.n);
        return point.mul(s);
    }

    // Point addition
    add(p1, p2) {
        return p1.add(p2);
    }

    // Get a random scalar in Zq
    getRandomScalar() {
        let r;
        do {
            r = new BN(crypto.randomBytes(32));
        } while (r.cmp(this.n) >= 0 || r.isZero());
        return r;
    }

    // Helper to format point as hex string
    pointToHex(point, compressed = true) {
        return point.encode('hex', compressed);
    }

    // Helper to parse hex string to point
    hexToPoint(hex) {
        return ec.curve.decodePoint(hex, 'hex');
    }
}

module.exports = new CurveGroup();
