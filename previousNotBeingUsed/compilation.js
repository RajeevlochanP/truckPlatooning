import fs from "fs/promises";
import { initialize } from "zokrates-js";


const zokratesProvider = await initialize()

const source = await fs.readFile("./public/path.zok", "utf8");

// compilation
console.log("Compiling the source code...");
const zk_artifacts = zokratesProvider.compile(source);
// console.log("ZK artifacts: ", JSON.stringify(zk_artifacts.abi));

//collecting only needed fields from zk_artifacts
const serializable = {
  program: Buffer.from(zk_artifacts.program).toString("base64"),
  abi: zk_artifacts.abi,
  constraints: zk_artifacts.constraints,
  symbols: zk_artifacts.symbols
};

//setup part but need to do only once thats why changed to compilation.js

//write artifacts to file
await fs.writeFile(
  "./public/zk_artifacts.json",
  JSON.stringify(serializable)
);

console.log("Generating keypair...");
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


// send the verifier key to chain
console.log("sending VK to chain..");
const response_vk = await fetch("http://localhost:3000/verifier-key", {
    method: "POST",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify({ verifierKey: keypair.vk })
});