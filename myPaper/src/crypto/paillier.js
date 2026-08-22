const crypto = require('crypto');
const bma = require('bigint-mod-arith');

function gcd(a, b) {
    while (b !== 0n) {
        let temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

function lcm(a, b) {
    return (a * b) / gcd(a, b);
}

function modInverse(a, m) {
    return bma.modInv(a, m);
}

function modPow(b, e, m) {
    if (e < 0n) {
        b = bma.modInv(b, m);
        e = -e;
    }
    b = b % m;
    if (b < 0n) b = (b + m) % m;
    return bma.modPow(b, e, m);
}

function randBigIntRange(max) {
    if (max <= 0n) return 0n;
    const bitLength = max.toString(2).length;
    const byteLength = Math.ceil(bitLength / 8);
    const topBitMask = (1 << (bitLength % 8 === 0 ? 8 : bitLength % 8)) - 1;

    while (true) {
        const buf = crypto.randomBytes(byteLength);
        buf[0] &= topBitMask; 
        const r = BigInt('0x' + buf.toString('hex'));
        if (r < max) return r;
    }
}

function randBigInt(bits) {
    const bytes = Math.ceil(bits / 8);
    const buf = crypto.randomBytes(bytes);
    buf[0] |= 0x80;
    buf[bytes - 1] |= 0x01;
    return BigInt('0x' + buf.toString('hex'));
}

function millerRabin(n, k = 40) {
    if (n === 2n || n === 3n) return true;
    if (n < 2n || n % 2n === 0n) return false;
    let d = n - 1n;
    let s = 0n;
    while (d % 2n === 0n) {
        d /= 2n;
        s += 1n;
    }
    for (let i = 0; i < k; i++) {
        let a = randBigIntRange(n - 3n) + 2n;
        let x = modPow(a, d, n);
        if (x === 1n || x === n - 1n) continue;
        let p = false;
        for (let j = 0n; j < s - 1n; j++) {
            x = modPow(x, 2n, n);
            if (x === 1n) return false;
            if (x === n - 1n) {
                p = true;
                break;
            }
        }
        if (!p) return false;
    }
    return true;
}

function generatePrime(bits) {
    while (true) {
        let p = randBigInt(bits);
        if (millerRabin(p)) return p;
    }
}

function generatePaillierKeypair(bits = 2048) {
    const p = generatePrime(bits / 2);
    const q = generatePrime(bits / 2);
    const N = p * q;
    const N2 = N * N;
    const g = N + 1n;
    const lambda = lcm(p - 1n, q - 1n);
    const L = (u) => (u - 1n) / N;
    const mu = modInverse(L(modPow(g, lambda, N2)), N);
    
    return {
        pub: { N, N2, g },
        priv: { lambda, mu, p, q }
    };
}

module.exports = {
    gcd, lcm, modInverse, modPow, randBigIntRange, generatePaillierKeypair
};
