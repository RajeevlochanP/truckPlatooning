import crypto from 'crypto';

export function modPow(base, exp, mod) {
    let b = BigInt(base) % BigInt(mod);
    let e = BigInt(exp);
    const m = BigInt(mod);
    let result = 1n;
    if (b < 0n) b += m;
    if (e < 0n) {
        e = -e;
        b = modInverse(b, m); 
    }
    while (e > 0n) {
        if (e % 2n === 1n) result = (result * b) % m;
        b = (b * b) % m;
        e /= 2n;
    }
    return result;
}

export function modInverse(a, m) {
    let [old_r, r] = [BigInt(a), BigInt(m)];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
        const quotient = old_r / r;
        [old_r, r] = [r, old_r - quotient * r];
        [old_s, s] = [s, old_s - quotient * s];
    }
    return (old_s % BigInt(m) + BigInt(m)) % BigInt(m);
}

function generateChallenge(N, g, C, A) {
    const hash = crypto.createHash('sha256');
    hash.update(N.toString());
    hash.update(g.toString());
    hash.update(C.toString());
    hash.update(A.toString());
    return BigInt('0x' + hash.digest('hex'));
}

export function verifyProof(pubKey, C, proof) {
    const n = BigInt(pubKey.n);
    const g = BigInt(pubKey.g);
    const n2 = n * n;
    
    const A = BigInt(proof.A);
    const e = BigInt(proof.e);
    const z1 = BigInt(proof.z1);
    const z2 = BigInt(proof.z2);
    const ciphertext = BigInt(C);

    // 1. Verify Challenge Integrity
    const e_check = generateChallenge(n, g, ciphertext, A);
    
    if (e !== e_check) {
        return false;
    }

    // 2. Verify Mathematical Equality
    // LHS = g^z1 * z2^n mod n^2
    const g_z1 = modPow(g, z1, n2);
    const z2_n = modPow(z2, n, n2);
    const LHS = (g_z1 * z2_n) % n2;

    // RHS = A * C^e mod n^2
    const C_e = modPow(ciphertext, e, n2);
    const RHS = (A * C_e) % n2;

    return LHS === RHS;
}

export function verifyPathProofs(pubKey, encryptedPath, proofs) {
    const results = [];
    let allValid = true;

    for (let i = 0; i < encryptedPath.length; i++) {
        const isValid = verifyProof(pubKey, encryptedPath[i], proofs[i]);
        results.push({ index: i, valid: isValid });
        
        if (!isValid) {
            allValid = false;
        }
    }

    return { allValid, results };
}

export function parsePubKey(pubKey) {
    const n = BigInt(pubKey.n);
    return {
        n: n,
        g: BigInt(pubKey.g),
        n2: pubKey.n2 ? BigInt(pubKey.n2) : n * n,
    };
}
