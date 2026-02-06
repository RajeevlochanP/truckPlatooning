import * as bls from "@noble/bls12-381";

export function aggregatePKs(pks) {
  return bls.aggregatePublicKeys(pks);
}

export async function verifySignature(signature, message, publicKey) {
  return await bls.verify(signature, message, publicKey);
}

export async function verifyAuthProof(authProof, authPks) {
  const omegaAgg = Uint8Array.from(authProof.omegaAgg);
  const hash = Uint8Array.from(authProof.h);
  const pksAsUint8Arrays = authPks.map((bytes) => Uint8Array.from(bytes));
  const pkAgg = aggregatePKs(pksAsUint8Arrays);
  
  return await verifySignature(omegaAgg, hash, pkAgg);
}
