const crypto = require('crypto');
const curve = require('./CurveGroup');
const BN = require('bn.js');

function hashPoints(...points) {
    const hash = crypto.createHash('sha256');
    for (const p of points) {
        if (p instanceof BN) {
            hash.update(p.toString(16, 64));
        } else {
            hash.update(curve.pointToHex(p, true));
        }
    }
    return new BN(hash.digest());
}

class ZKP {
    // 1. Schnorr Proof for C = g^w * h^r
    static generateInitProof(w, r, C) {
        const wBN = new BN(w.toString());
        const rBN = new BN(r.toString(16), 16);
        
        const kw = curve.getRandomScalar();
        const kr = curve.getRandomScalar();
        
        const A = curve.add(curve.mul(curve.g, kw), curve.mul(curve.h, kr));
        
        const c = hashPoints(curve.g, curve.h, C, A).umod(curve.n);
        
        const zw = kw.sub(c.mul(wBN)).umod(curve.n);
        const zr = kr.sub(c.mul(rBN)).umod(curve.n);
        
        return { c: c.toString(16), zw: zw.toString(16), zr: zr.toString(16) };
    }

    static verifyInitProof(C, proof) {
        const c = new BN(proof.c, 16);
        const zw = new BN(proof.zw, 16);
        const zr = new BN(proof.zr, 16);
        
        // A' = g^zw * h^zr * C^c
        const A_prime = curve.add(
            curve.add(curve.mul(curve.g, zw), curve.mul(curve.h, zr)),
            curve.mul(C, c)
        );
        
        const c_prime = hashPoints(curve.g, curve.h, C, A_prime).umod(curve.n);
        return c.cmp(c_prime) === 0;
    }

    // 2. CDS 1-out-of-2 Proof for B = g^b * h^s
    static generateBitProof(b, s, B) {
        const sBN = new BN(s.toString(16), 16);
        const bNum = Number(b);
        
        const k = curve.getRandomScalar();
        const c_fake = curve.getRandomScalar();
        const z_fake = curve.getRandomScalar();
        
        let c0, c1, z0, z1, A0, A1;
        
        if (bNum === 0) {
            c1 = c_fake;
            z1 = z_fake;
            
            // A1 = h^z1 * (B/g)^c1
            const B_div_g = curve.add(B, curve.mul(curve.g, curve.n.sub(new BN(1))));
            A1 = curve.add(curve.mul(curve.h, z1), curve.mul(B_div_g, c1));
            
            // A0 = h^k
            A0 = curve.mul(curve.h, k);
            
            const c = hashPoints(B, A0, A1).umod(curve.n);
            c0 = c.sub(c1).umod(curve.n);
            z0 = k.sub(c0.mul(sBN)).umod(curve.n);
        } else {
            c0 = c_fake;
            z0 = z_fake;
            
            // A0 = h^z0 * B^c0
            A0 = curve.add(curve.mul(curve.h, z0), curve.mul(B, c0));
            
            // A1 = h^k
            A1 = curve.mul(curve.h, k);
            
            const c = hashPoints(B, A0, A1).umod(curve.n);
            c1 = c.sub(c0).umod(curve.n);
            z1 = k.sub(c1.mul(sBN)).umod(curve.n);
        }
        
        return {
            c0: c0.toString(16),
            c1: c1.toString(16),
            z0: z0.toString(16),
            z1: z1.toString(16)
        };
    }

    static verifyBitProof(B, proof) {
        const c0 = new BN(proof.c0, 16);
        const c1 = new BN(proof.c1, 16);
        const z0 = new BN(proof.z0, 16);
        const z1 = new BN(proof.z1, 16);
        
        // A0' = h^z0 * B^c0
        const A0 = curve.add(curve.mul(curve.h, z0), curve.mul(B, c0));
        
        // A1' = h^z1 * (B/g)^c1
        const B_div_g = curve.add(B, curve.mul(curve.g, curve.n.sub(new BN(1))));
        const A1 = curve.add(curve.mul(curve.h, z1), curve.mul(B_div_g, c1));
        
        const c_expected = c0.add(c1).umod(curve.n);
        const c_actual = hashPoints(B, A0, A1).umod(curve.n);
        
        return c_expected.cmp(c_actual) === 0;
    }

    // 3. Linear Consistency Proof for \prod B_j^{2^j} / C = h^{\Delta s}
    static generateLinProof(C, B_arr, s_arr, r) {
        const rBN = new BN(r.toString(16), 16);
        let delta_s = curve.n.sub(rBN); // -r
        
        let B_prod = null;
        for (let j = 0; j < B_arr.length; j++) {
            const two_j = new BN(1).shln(j);
            const B_pow = curve.mul(B_arr[j], two_j);
            if (B_prod === null) B_prod = B_pow;
            else B_prod = curve.add(B_prod, B_pow);
            
            const s_BN = new BN(s_arr[j].toString(16), 16);
            delta_s = delta_s.add(s_BN.mul(two_j)).umod(curve.n);
        }
        
        const C_inv = curve.mul(C, curve.n.sub(new BN(1)));
        const target = curve.add(B_prod, C_inv); // target = h^{\Delta s}
        
        const k = curve.getRandomScalar();
        const A = curve.mul(curve.h, k);
        const c = hashPoints(target, A).umod(curve.n);
        const z = k.sub(c.mul(delta_s)).umod(curve.n);
        
        return { c: c.toString(16), z: z.toString(16) };
    }

    static verifyLinProof(C, B_arr, proof) {
        let B_prod = null;
        for (let j = 0; j < B_arr.length; j++) {
            const two_j = new BN(1).shln(j);
            const B_pow = curve.mul(B_arr[j], two_j);
            if (B_prod === null) B_prod = B_pow;
            else B_prod = curve.add(B_prod, B_pow);
        }
        
        const C_inv = curve.mul(C, curve.n.sub(new BN(1)));
        const target = curve.add(B_prod, C_inv);
        
        const c = new BN(proof.c, 16);
        const z = new BN(proof.z, 16);
        
        // A' = h^z * target^c
        const A_prime = curve.add(curve.mul(curve.h, z), curve.mul(target, c));
        const c_prime = hashPoints(target, A_prime).umod(curve.n);
        
        return c.cmp(c_prime) === 0;
    }
}

module.exports = ZKP;
