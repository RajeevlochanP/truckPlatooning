const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');

const Applicant = require('../myPaper/src/core/Applicant');
const Leader = require('../myPaper/src/core/Leader');
const SmartContract = require('../myPaper/src/core/SmartContract');
const CU = require('../TAROT/src/core/CU');

function parseBigInts(obj) {
    if (typeof obj === 'string') {
        try {
            return BigInt(obj);
        } catch(e) {
            return obj;
        }
    }
    if (Array.isArray(obj)) return obj.map(parseBigInts);
    if (obj !== null && typeof obj === 'object') {
        const res = {};
        for (const [k, v] of Object.entries(obj)) {
            res[k] = parseBigInts(v);
        }
        return res;
    }
    return obj;
}

const hePsiKeysPath = path.join(__dirname, '../myPaper/keys.json');
const tarotKeysPath = path.join(__dirname, '../TAROT/keys.json');

if (!fs.existsSync(hePsiKeysPath)) {
    console.error(`HE-PSI keys not found at ${hePsiKeysPath}`);
    process.exit(1);
}
if (!fs.existsSync(tarotKeysPath)) {
    console.error(`TAROT keys not found at ${tarotKeysPath}`);
    process.exit(1);
}

// Load HE-PSI Keys
const hePsiKeysRaw = JSON.parse(fs.readFileSync(hePsiKeysPath, 'utf8'));
const hePsiKeys = parseBigInts(hePsiKeysRaw);
const keyA = hePsiKeys.Applicant;
const keyL = hePsiKeys.Leader;

const applicant = new Applicant(keyA, keyL.pub);
const leader = new Leader(keyL, keyA.pub);
const sc = new SmartContract(keyA.pub, keyL.pub);

// Load TAROT Keys
const tarotKeysRaw = JSON.parse(fs.readFileSync(tarotKeysPath, 'utf-8'));
const pk = {
    n: BigInt(tarotKeysRaw.publicKey.n),
    g: BigInt(tarotKeysRaw.publicKey.g)
};
const sk = {
    p: BigInt(tarotKeysRaw.privateKey.p),
    q: BigInt(tarotKeysRaw.privateKey.q)
};

const pathLengths = [10, 20, 30, 40, 50];
const csvPath = path.join(__dirname, 'benchmark_latency.csv');

// Initialize CSV
const csvHeader = "PathLength(l),HE_PSI_T_A_ms,HE_PSI_SC_ms,HE_PSI_T_L_ms,HE_PSI_Total_ms,TAROT_Eval_ms,TAROT_Dec_ms,TAROT_Total_ms";
let csvContent = csvHeader + "\n";
console.log(csvHeader);

for (const l of pathLengths) {
    // ==== HE-PSI OFFLINE PRECOMPUTATION ====
    const routeA = Array.from({length: l}, (_, i) => BigInt(i + 100));
    const routeL = Array.from({length: l}, (_, i) => BigInt(i + 100)); // matching route
    
    const commsA = routeA.map(w => applicant.commitWaypoint(w));
    const commsL = routeL.map(w => leader.commitWaypoint(w));
    const statesA = commsA.map(cA => applicant.precomputeEval(cA.C_A_inv));
    
    // ==== TAROT OFFLINE PRECOMPUTATION ====
    const trajA = Array.from({ length: l }, (_, i) => 1000 + i);
    const trajB = Array.from({ length: l }, (_, i) => 1000 + i); 
    const encTrajA = trajA.map(wp => CU.encryptWaypoint(wp, pk));
    const encTrajB = trajB.map(wp => CU.encryptWaypoint(wp, pk));

    // ==== HE-PSI ONLINE PHASE ====
    let t_a_ms = 0;
    let sc_verify_ms = 0;
    let t_l_dec_ms = 0;
    
    let C_A_arr = [], C_L_arr = [], C_beta_arr = [], C_blind_arr = [], pi_eval_arr = [], pi_final_arr = [];

    // HE-PSI Applicant Generation (Online)
    for (let i = 0; i < l; i++) {
        const cA = commsA[i];
        const cL = commsL[i];
        const state = statesA[i];
        
        C_A_arr.push(cA.C_x);
        C_L_arr.push(cL.C_x);
        
        let t0 = performance.now();
        const { C_beta, C_blind, pi_eval } = applicant.evaluateMatch(cA.w, cA.C_x, cA.C_A_inv, cA.r_A_inv, cL.C_x, state);
        let t1 = performance.now();
        t_a_ms += (t1 - t0);
        
        C_beta_arr.push(C_beta);
        C_blind_arr.push(C_blind);
        pi_eval_arr.push(pi_eval);
    }

    // HE-PSI SC Verify 1 (Online)
    let t0 = performance.now();
    const isValid = sc.verifyEvalProofBatch(C_A_arr, C_L_arr, C_beta_arr, C_blind_arr, pi_eval_arr);
    let t1 = performance.now();
    sc_verify_ms += (t1 - t0);

    if (!isValid) {
        console.error("Smart Contract Verification Failed for batch!");
        process.exit(1);
    }

    // HE-PSI Leader Decrypt (Online)
    for (let i = 0; i < l; i++) {
        let t0 = performance.now();
        const { isMatch, m_true, pi_final } = leader.decideMatch(C_blind_arr[i]);
        let t1 = performance.now();
        t_l_dec_ms += (t1 - t0);
        pi_final_arr.push(pi_final);
        
        if (!isMatch) {
            console.error("Match failed for identical waypoint!");
            process.exit(1);
        }
    }

    // HE-PSI SC Verify 2 (Online)
    t0 = performance.now();
    const isFinalValid = sc.verifyFinalProofBatch(C_blind_arr, pi_final_arr, keyL.pub);
    t1 = performance.now();
    sc_verify_ms += (t1 - t0);

    if (!isFinalValid) {
        console.error("Smart Contract Verification of Final Proof Failed for batch!");
        process.exit(1);
    }
    
    const hePsiTotal_ms = t_a_ms + sc_verify_ms + t_l_dec_ms;

    // ==== TAROT ONLINE PHASE ====
    const evaluatedE = new Array(l);

    // TAROT Eval (Online)
    const startEval = performance.now();
    for (let i = 0; i < l; i++) {
        evaluatedE[i] = CU.evaluateEquality(encTrajA[i], encTrajB[i], pk.n);
    }
    const evalMs = performance.now() - startEval;

    // TAROT Dec (Online)
    const startDec = performance.now();
    for (let i = 0; i < l; i++) {
        const isMatch = CU.decryptAndDecide(evaluatedE[i], sk);
    }
    const decMs = performance.now() - startDec;

    const tarotTotal_ms = evalMs + decMs;

    // Output formatting
    const row = `${l},${t_a_ms.toFixed(3)},${sc_verify_ms.toFixed(3)},${t_l_dec_ms.toFixed(3)},${hePsiTotal_ms.toFixed(3)},${evalMs.toFixed(3)},${decMs.toFixed(3)},${tarotTotal_ms.toFixed(3)}`;
    console.log(row);
    csvContent += row + "\n";
}

fs.writeFileSync(csvPath, csvContent, 'utf8');
console.log(`\nBenchmarks completed. Results saved to benchmark_latency.csv`);
