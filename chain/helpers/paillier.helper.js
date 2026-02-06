import bigInt from 'big-integer';
import crypto from 'crypto';

function generateChallenge(N, g, C, A) {
  const hash = crypto.createHash('sha256');
  hash.update(N.toString());
  hash.update(g.toString());
  hash.update(C.toString());
  hash.update(A.toString());
  
  const hex = hash.digest('hex');
  return bigInt(hex, 16);
}

export function verifyProof(pubKey, C, proof) {
    const { n, g} = pubKey;
    const n2= bigInt(n.toString()).multiply(bigInt(n.toString())); // n²
    const A = bigInt(proof.A);
    const e = bigInt(proof.e);
    const z1 = bigInt(proof.z1);
    const z2 = bigInt(proof.z2);
    const ciphertext = bigInt(C);

    // 1. Verify Challenge Integrity
    const e_check = generateChallenge(n, g, ciphertext, A);
    
    if (e.neq(e_check)) {
        return false;
    }

    // 2. Verify Mathematical Equality
    // LHS = g^z1 * z2^n mod n^2
    const g_z1 = g.modPow(z1, n2);
    const z2_n = z2.modPow(n, n2);
    const LHS = g_z1.multiply(z2_n).mod(n2);

    // RHS = A * C^e mod n^2
    const C_e = ciphertext.modPow(e, n2);
    const RHS = A.multiply(C_e).mod(n2);

    return LHS.eq(RHS);
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
  return {
    n: bigInt(pubKey.n),
    g: bigInt(pubKey.g),
    n2: bigInt(pubKey.n2),
  };
}
