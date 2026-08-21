const crypto = require('crypto');

function sha256BigInt(...args) {
    const hash = crypto.createHash('sha256');
    for (const arg of args) {
        hash.update(arg.toString());
    }
    return BigInt('0x' + hash.digest('hex'));
}

module.exports = {
    sha256BigInt
};
