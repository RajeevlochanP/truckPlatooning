const crypto = require('crypto');

function modPow(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
        if (exponent % 2n === 1n) {
            result = (result * base) % modulus;
        }
        exponent = exponent / 2n;
        base = (base * base) % modulus;
    }
    return result;
}

function getRandomBigInt(max) {
    const hex = max.toString(16);
    const byteLen = Math.ceil(hex.length / 2);
    let rand;
    do {
        const buf = crypto.randomBytes(byteLen);
        rand = BigInt('0x' + buf.toString('hex'));
    } while (rand >= max || rand === 0n);
    return rand;
}

function generateKeys() {
    // Generate two 1024-bit primes
    const p = crypto.generatePrimeSync(1024, { bigint: true });
    const q = crypto.generatePrimeSync(1024, { bigint: true });
    const n = p * q;

    let g;
    do {
        g = getRandomBigInt(n);
    // Find g such that (g/p) = -1 and (g/q) = -1
    } while (modPow(g, (p - 1n) / 2n, p) !== p - 1n || modPow(g, (q - 1n) / 2n, q) !== q - 1n);

    return {
        publicKey: { n, g },
        privateKey: { p, q }
    };
}

function encryptBit(m, pk) {
    const { n, g } = pk;
    const r = getRandomBigInt(n);
    const r2 = modPow(r, 2n, n);
    if (m === 0n || m === 0) {
        return r2;
    } else {
        return (g * r2) % n;
    }
}

function decryptBit(c, sk) {
    const { p } = sk;
    const j = modPow(c, (p - 1n) / 2n, p);
    if (j === 1n) return 0;
    if (j === p - 1n) return 1;
    throw new Error("Invalid ciphertext. Jacobi symbol was not 1 or -1.");
}

module.exports = {
    generateKeys,
    encryptBit,
    decryptBit,
    modPow
};
