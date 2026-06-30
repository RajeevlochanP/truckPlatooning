import crypto from 'crypto';

export const DH_P = BigInt("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF");
export const DH_G = 2n;

export function modPow(base, exp, mod) {
    let b = BigInt(base) % BigInt(mod);
    let e = BigInt(exp);
    const m = BigInt(mod);
    let result = 1n;
    if (b < 0n) b += m;
    while (e > 0n) {
        if (e % 2n === 1n) result = (result * b) % m;
        b = (b * b) % m;
        e /= 2n;
    }
    return result;
}

export function randDHSecret() {
    // Generate a random 256-bit secret
    const buffer = crypto.randomBytes(32);
    return BigInt('0x' + buffer.toString('hex'));
}

export class TGDHNode {
    constructor(id, isLeaf = false) {
        this.id = id;
        this.isLeaf = isLeaf;
        this.privateKey = null; // x
        this.publicKey = null;  // y = g^x mod p
        this.left = null;
        this.right = null;
    }

    setPrivateKey(x) {
        this.privateKey = BigInt(x);
        this.publicKey = modPow(DH_G, this.privateKey, DH_P);
    }

    // Combine left and right children to compute this node's keys
    computeFromChildren() {
        if (!this.left || !this.right) throw new Error("Cannot compute, missing children");
        if (!this.left.publicKey || !this.right.publicKey) throw new Error("Children missing public keys");
        
        // Simulating the interaction: 
        // In reality, Left computes K = Right.y ^ Left.x mod p
        // Right computes K = Left.y ^ Right.x mod p
        // Both derive the same K.
        const K_left = modPow(this.right.publicKey, this.left.privateKey, DH_P);
        const K_right = modPow(this.left.publicKey, this.right.privateKey, DH_P);
        
        if (K_left !== K_right) throw new Error("DH Key mismatch!");

        this.setPrivateKey(K_left);
        return this.publicKey;
    }
}
