import { poseidon2 } from 'poseidon-lite'

const adj = [
    ..."0 1 0 1 0 0 0 0 0 0 0 0 0 0 0 0".split(" "),  // row 0: edge 1→2
  ..."0 0 1 0 1 0 1 0 0 0 0 0 0 0 0 0".split(" "),  // row 1: edge 2→3
  ..."0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0".split(" "),  // row 2
  ..."0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0".split(" "),  // row 3
  ..."0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0".split(" "),  // row 4
  ..."0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0".split(" "),  // row 5
  ..."0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0".split(" "),  // row 6
  ..."0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0".split(" "),  // row 7
  ...Array(8 * 16).fill("0")
];

const N = 16;
let h_adj = 0n;


for (let row = 0; row < N; row++) {
    let row_packed = 0n;
    let mult = 1n;           // represents (2^col) as BigInt
    for (let col = 0; col < N; col++) {
        let idx = row * N + col;
        // console.log(adj[idx], {row, col, idx});
        row_packed += BigInt(adj[idx]) * mult;
        mult *= 2n;          // next power of two
    }
    h_adj = poseidon2([h_adj, row_packed]);
}

h_adj = h_adj.toString();

const pub_path = ["1","2","7", "5", "6", ...Array(11).fill("0")];

let hash_pubpath = 0;
for (let i = 0; i < pub_path.length; i++) {
    hash_pubpath = poseidon2([hash_pubpath, BigInt(pub_path[i])]);
}

hash_pubpath = hash_pubpath.toString();

const pub_len = "5";

export {
    adj,
    pub_path,
    pub_len,
    hash_pubpath,
    h_adj
}