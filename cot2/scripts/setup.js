const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const curve = require('../core/CurveGroup');

function setup() {
    const configDir = path.join(__dirname, '../config');
    if (!fs.existsSync(configDir)) fs.mkdirSync(configDir);

    // 1. Generate Public Params
    const publicParams = {
        curve: 'secp256k1',
        n: curve.n.toString(16),
        p: curve.p.toString(16),
        g: curve.pointToHex(curve.g, true),
        h: curve.pointToHex(curve.h, true)
    };
    
    fs.writeFileSync(path.join(configDir, 'public_params.json'), JSON.stringify(publicParams, null, 2));

    // 2. Generate Long-term Vehicle Keys
    // Applicant
    const skA = crypto.randomBytes(32);
    const pkA = crypto.createECDH('secp256k1');
    pkA.setPrivateKey(skA);

    // Leader
    const skL = crypto.randomBytes(32);
    const pkL = crypto.createECDH('secp256k1');
    pkL.setPrivateKey(skL);

    const keys = {
        Applicant: {
            pub: pkA.getPublicKey('hex'),
            priv: skA.toString('hex')
        },
        Leader: {
            pub: pkL.getPublicKey('hex'),
            priv: skL.toString('hex')
        }
    };

    fs.writeFileSync(path.join(configDir, 'keys.json'), JSON.stringify(keys, null, 2));

    console.log("Offline keys and parameters precomputed successfully.");
}

setup();
