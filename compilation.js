import fs from "fs/promises";
import { initialize } from "zokrates-js";


const zokratesProvider = await initialize()

const source = await fs.readFile("./public/path.zok", "utf8");

// compilation
const zk_artifacts = zokratesProvider.compile(source);
// console.log("ZK artifacts: ", JSON.stringify(zk_artifacts.abi));

//collecting only needed fields from zk_artifacts
const serializable = {
  program: Buffer.from(zk_artifacts.program).toString("base64"),
  abi: zk_artifacts.abi,
  constraints: zk_artifacts.constraints,
  symbols: zk_artifacts.symbols
};

//write artifacts to file
await fs.writeFile(
  "./public/zk_artifacts.json",
  JSON.stringify(serializable)
);