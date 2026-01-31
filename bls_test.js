import * as bls from '@noble/bls12-381';


function keyGen() {
    const sk = bls.utils.randomPrivateKey();   // α
    const pk = bls.getPublicKey(sk);           // g^α
    return { sk, pk };
}

async function H_to_G1(message) {
    // noble-bls12-381 provides a hash-to-curve helper in utils:
    // blsUtils.hashToG1(msg) returns PointG1
    // If not present, try PointG1.hashToCurve(msg)
    if (typeof blsUtils.hashToG1 === "function") {
        console.log("A");
        
        return await blsUtils.hashToG1(message);
    }
    if (PointG1.hashToCurve) {
        console.log("B");
        return PointG1.hashToCurve(message);
    }
    throw new Error("No hash-to-G1 helper found in this library version.");
}

async function proofGen(h, sk) {
    const omega = await bls.sign(h, sk); // = h^sk
    return omega;
}

function aggregateProofs(proofs) {
    return bls.aggregateSignatures(proofs);
}

function aggregatePKs(pks) {
    return bls.aggregatePublicKeys(pks);
}


async function verifyProof(omega, h, pk) {
    return await bls.verify(omega, h, pk);
}



// Demo: three trucks (λ=3)
async function demo() {
    const message = "one-time-secret-identifier-13"; // m

    const h = new TextEncoder().encode(message);
    const hPoint = await bls.PointG1.hashToCurve(h);
    console.log("H(m) point:", hPoint);

    // CA: create keys for 3 trucks
    const trucks = [];
    for (let i = 0; i < 3; i++) {
        const { sk, pk } = keyGen();
        trucks.push({ sk, pk });
    }


    console.log({ trucks });

    // Each truck computes its one-time proof Omega_λ = h^sk
    const proofs = [];
    const pks = [];
    //   const h = oneTimeHash(message);
    for (const t of trucks) {
        console.log({t: t.sk});
        
        const omega = await proofGen(h, t.sk);
        // store h (same for all) and omega per truck
        proofs.push(omega);
        pks.push(t.pk);
    }


    
    // Aggregate Omegas (G1) and PKs (G2)
    const omegaAgg = aggregateProofs(proofs);
    const pkAgg = aggregatePKs(pks);

    console.log({omegaAgg, h, pkAgg});

    // Verify
    const ok = await verifyProof(omegaAgg, h, pkAgg);
    console.log("pairing verified:", ok);

}

demo().catch(console.error);