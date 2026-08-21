const fs = require('fs');
const path = require('path');
const { generateKeys } = require('../src/crypto/gm');

const keysPath = path.join(__dirname, '..', 'keys.json');

console.log("Generating 2048-bit GM keys (this may take a few seconds)...");
const start = Date.now();
const keys = generateKeys();
const end = Date.now();

const keysJSON = {
    publicKey: {
        n: keys.publicKey.n.toString(),
        g: keys.publicKey.g.toString()
    },
    privateKey: {
        p: keys.privateKey.p.toString(),
        q: keys.privateKey.q.toString()
    }
};

fs.writeFileSync(keysPath, JSON.stringify(keysJSON, null, 2));
console.log(`Keys generated and saved to ${keysPath} in ${end - start}ms`);
