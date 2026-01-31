import fs from "fs/promises";
import { initialize } from "zokrates-js";
import * as dotenv from "dotenv";
import * as bls from '@noble/bls12-381';

dotenv.config({ quiet: true });
const zokratesProvider = await initialize();

// load zk artifacts
const zk_artifacts = JSON.parse(
  await fs.readFile("./public/zk_artifacts.json", "utf8")
);
zk_artifacts.program = Buffer.from(zk_artifacts.program, "base64");

// run setup
const keypair = zokratesProvider.setup(zk_artifacts.program);
// console.log(keypair);



//write keypair to file

// prover key
await fs.writeFile(
  "./private/prover_key.json",
  JSON.stringify(keypair.pk)
);

// verifier key
await fs.writeFile(
  "./public/verifier_key.json",
  JSON.stringify(keypair.vk)
);


// // export solidity verifier
// const verifier = zokratesProvider.exportSolidityVerifier(keypair.vk);
// //write verifier to file
// await fs.writeFile(
//   "./public/verifier.sol",
//   verifier
// );



function keyGen() {
    const sk = bls.utils.randomPrivateKey();   // α
    const pk = bls.getPublicKey(sk);           // g^α
    return { sk, pk };
}

// CA: create keys for 3 trucks
const authKeypair = {pk: [], sk: []};
for (let i = 0; i < 3; i++) {
    const { sk, pk } = keyGen();
    authKeypair.pk.push(pk);
    authKeypair.sk.push(sk);
}

const serialized_pk = authKeypair.pk.map(pk => [...pk]);


// Auth keypair for one-time use
await fs.writeFile(
  "./public/auth_pk.json",
  JSON.stringify(serialized_pk)
);

const serialized_sk = authKeypair.sk.map(sk => [...sk]);

await fs.writeFile(
  "./private/auth_sk.json",
  JSON.stringify(serialized_sk)
);
