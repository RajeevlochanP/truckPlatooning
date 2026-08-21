const fs = require('fs');
const path = require('path');
const { generatePaillierKeypair } = require('../src/crypto/paillier');

const keysPath = path.join(__dirname, '../keys.json');

function stringifyBigInts(obj) {
    if (typeof obj === 'bigint') return obj.toString();
    if (Array.isArray(obj)) return obj.map(stringifyBigInts);
    if (obj !== null && typeof obj === 'object') {
        const res = {};
        for (const [k, v] of Object.entries(obj)) {
            res[k] = stringifyBigInts(v);
        }
        return res;
    }
    return obj;
}

if (fs.existsSync(keysPath)) {
    console.log('keys.json already exists. Loading directly is supported in benchmark.js');
    process.exit(0);
}

console.log('Generating 2048-bit Paillier keys for Applicant (T_A)...');
const keyA = generatePaillierKeypair(2048);
console.log('Generating 2048-bit Paillier keys for Leader (T_L)...');
const keyL = generatePaillierKeypair(2048);

const output = {
    Applicant: stringifyBigInts(keyA),
    Leader: stringifyBigInts(keyL)
};

fs.writeFileSync(keysPath, JSON.stringify(output, null, 2));
console.log('Keys generated and saved to keys.json');
