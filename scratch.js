const crypto = require('crypto');

function randBigInt(bits) {
    const bytes = Math.ceil(bits / 8);
    const buf = crypto.randomBytes(bytes);
    buf[0] |= (1 << ((bits - 1) % 8)); // Set MSB
    let hex = buf.toString('hex');
    let extraBits = (bytes * 8) - bits;
    if (extraBits > 0) {
        // We actually want exactly 'bits' bits. 
        // e.g., if bits = 10, bytes = 2. buf[0] MSB set. 
    }
    return BigInt('0x' + buf.toString('hex'));
}

function modPow(b, e, m) {
    let r = 1n;
    b = b % m;
    while (e > 0n) {
        if (e & 1n) r = (r * b) % m;
        e >>= 1n;
        b = (b * b) % m;
    }
    return r;
}

function millerRabin(n, k = 20) {
    if (n === 2n || n === 3n) return true;
    if (n < 2n || n % 2n === 0n) return false;
    let d = n - 1n;
    let s = 0n;
    while (d % 2n === 0n) {
        d /= 2n;
        s += 1n;
    }
    for (let i = 0; i < k; i++) {
        let buf = crypto.randomBytes(128); // 1024 bits max roughly
        let a = BigInt('0x' + buf.toString('hex')) % (n - 3n) + 2n;
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
        const bytes = crypto.randomBytes(bits / 8);
        bytes[0] |= 0x80; // set top bit
        bytes[bytes.length - 1] |= 0x01; // set bottom bit
        let p = BigInt('0x' + bytes.toString('hex'));
        if (millerRabin(p, 5)) return p; // 5 rounds is enough for test
    }
}

console.time('gen1024');
const p = generatePrime(1024);
console.timeEnd('gen1024');
console.log(p.toString(16).length);
