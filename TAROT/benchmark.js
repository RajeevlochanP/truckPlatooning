const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');
const CU = require('./src/core/CU');

const keysPath = path.join(__dirname, 'keys.json');
if (!fs.existsSync(keysPath)) {
    console.error("keys.json not found. Please run scripts/generateKeys.js first.");
    process.exit(1);
}

// 1. Load Keys (Zero I/O in Timers)
const keysRaw = JSON.parse(fs.readFileSync(keysPath, 'utf-8'));
const pk = {
    n: BigInt(keysRaw.publicKey.n),
    g: BigInt(keysRaw.publicKey.g)
};
const sk = {
    p: BigInt(keysRaw.privateKey.p),
    q: BigInt(keysRaw.privateKey.q)
};

const pathLengths = [10, 20, 30, 40, 50];
const csvPath = path.join(__dirname, 'benchmark_results.csv');

// Initialize CSV
fs.writeFileSync(csvPath, "PathLength(l),CU_j_Eval_ms,CU_i_Dec_ms,Total_ms\n");

console.log("Starting TAROT (GMEDA) Benchmarks...\n");

for (const l of pathLengths) {
    // Generate matching dummy trajectories to force the worst-case scenario (all 32 bits decrypted)
    const trajA = Array.from({ length: l }, (_, i) => 1000 + i);
    const trajB = Array.from({ length: l }, (_, i) => 1000 + i); 

    // OFFLINE PHASE: Encrypt all waypoints outside the timer loops
    const encTrajA = trajA.map(wp => CU.encryptWaypoint(wp, pk));
    const encTrajB = trajB.map(wp => CU.encryptWaypoint(wp, pk));

    const evaluatedE = new Array(l);

    // ONLINE PHASE: CU_j Eval
    const startEval = performance.now();
    for (let i = 0; i < l; i++) {
        evaluatedE[i] = CU.evaluateEquality(encTrajA[i], encTrajB[i], pk.n);
    }
    const endEval = performance.now();
    const evalMs = endEval - startEval;

    // ONLINE PHASE: CU_i Dec
    const startDec = performance.now();
    for (let i = 0; i < l; i++) {
        const isMatch = CU.decryptAndDecide(evaluatedE[i], sk);
    }
    const endDec = performance.now();
    const decMs = endDec - startDec;

    const totalMs = evalMs + decMs;

    console.log(`Length: ${l} | Eval: ${evalMs.toFixed(2)} ms | Dec: ${decMs.toFixed(2)} ms | Total: ${totalMs.toFixed(2)} ms`);
    fs.appendFileSync(csvPath, `${l},${evalMs.toFixed(2)},${decMs.toFixed(2)},${totalMs.toFixed(2)}\n`);
}

console.log(`\nBenchmarks completed. Results saved to benchmark_results.csv`);
