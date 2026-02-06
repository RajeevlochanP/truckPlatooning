import * as bls from '@noble/bls12-381';
export async function proofGen(h, sk) {
    const omega = await bls.sign(h, sk); // = h^sk
    return omega;
}

export function aggregateProofs(proofs) {
    return bls.aggregateSignatures(proofs);
}