const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');

// HE-PSI legacy imports
const Applicant = require('../myPaper/src/core/Applicant');
const Leader = require('../myPaper/src/core/Leader');
const SmartContract = require('../myPaper/src/core/SmartContract');

// COT-PE imports
const COTPEEngine = require('../cot2/engine/COTPEEngine');

function parseBigInts(obj) {
    if (typeof obj === 'string') {
        try { return BigInt(obj); } catch(e) { return obj; }
    }
    if (Array.isArray(obj)) return obj.map(parseBigInts);
    if (obj !== null && typeof obj === 'object') {
        const res = {};
        for (const [k, v] of Object.entries(obj)) res[k] = parseBigInts(v);
        return res;
    }
    return obj;
}

// ==== LOAD OFFLINE KEYS (EXCLUDED FROM ONLINE LATENCY) ====
const hePsiKeysPath = path.join(__dirname, '../myPaper/keys.json');
const cotpeKeysPath = path.join(__dirname, '../cot2/config/keys.json');
const cotpeParamsPath = path.join(__dirname, '../cot2/config/public_params.json');

if (!fs.existsSync(hePsiKeysPath)) { console.error(`HE-PSI keys not found`); process.exit(1); }
if (!fs.existsSync(cotpeKeysPath)) { console.error(`COT-PE keys not found`); process.exit(1); }

const hePsiKeys = parseBigInts(JSON.parse(fs.readFileSync(hePsiKeysPath, 'utf8')));
const keyA = hePsiKeys.Applicant;
const keyL = hePsiKeys.Leader;
const applicant = new Applicant(keyA, keyL.pub);
const leader = new Leader(keyL, keyA.pub);
const sc = new SmartContract(keyA.pub, keyL.pub);

// Note: COT-PE keys are loaded during setup, but engine instantiates dynamically.
// Loading them here to prove zero-cost online setup.
JSON.parse(fs.readFileSync(cotpeKeysPath, 'utf8'));
JSON.parse(fs.readFileSync(cotpeParamsPath, 'utf8'));

const pathLengths = [10, 20, 30, 40, 50];
const csvPath = path.join(__dirname, 'benchmark_latency.csv');

const csvHeader = "PathLength(l),HE_PSI_Total_ms,COTPE_Phase1,COTPE_Phase2,COTPE_Phase3,COTPE_Phase4,COTPE_Phase5,COTPE_Total_ms";
let csvContent = csvHeader + "\n";
console.log(csvHeader.replace(/,/g, ' | '));
console.log("-".repeat(120));

const cotpeEngine = new COTPEEngine();

// ==== 5-ITERATION WARMUP ====
console.log("Running 5-iteration warm-up...");
for (let i = 0; i < 5; i++) {
    const w = Array.from({length: 10}, (_, i) => i + 100);
    // Warmup HE-PSI
    const commsA = w.map(x => applicant.commitWaypoint(BigInt(x)));
    const commsL = w.map(x => leader.commitWaypoint(BigInt(x)));
    const statesA = commsA.map(cA => applicant.precomputeEval(cA.C_A_inv));
    const { C_beta, C_blind, pi_eval } = applicant.evaluateMatch(commsA[0].w, commsA[0].C_x, commsA[0].C_A_inv, commsA[0].r_A_inv, commsL[0].C_x, statesA[0]);
    // Warmup COT-PE
    cotpeEngine.runProtocol(w, w, 5);
}
console.log("Warm-up complete.\n");

for (const l of pathLengths) {
    const ITERATIONS = 10;
    
    let hepsi_total = 0;
    let cotpe_p1 = 0, cotpe_p2 = 0, cotpe_p3 = 0, cotpe_p4 = 0, cotpe_p5 = 0, cotpe_total = 0;

    for (let iter = 0; iter < ITERATIONS; iter++) {
        // Shared random routes for this iteration
        const routeA = Array.from({length: l}, (_, i) => i + 1000);
        const routeL = Array.from({length: l}, (_, i) => i + 1000); // 100% match

        // =====================================
        // HE-PSI
        // =====================================
        // Offline
        const commsA = routeA.map(w => applicant.commitWaypoint(BigInt(w)));
        const commsL = routeL.map(w => leader.commitWaypoint(BigInt(w)));
        const statesA = commsA.map(cA => applicant.precomputeEval(cA.C_A_inv));

        let C_A_arr = [], C_L_arr = [], C_beta_arr = [], C_blind_arr = [], pi_eval_arr = [], pi_final_arr = [];
        
        // Online HE-PSI sum
        let t_a = 0, sc_v1 = 0, t_l = 0, sc_v2 = 0;
        
        for (let i = 0; i < l; i++) {
            C_A_arr.push(commsA[i].C_x);
            C_L_arr.push(commsL[i].C_x);
            
            let t0 = performance.now();
            const res = applicant.evaluateMatch(commsA[i].w, commsA[i].C_x, commsA[i].C_A_inv, commsA[i].r_A_inv, commsL[i].C_x, statesA[i]);
            t_a += (performance.now() - t0);
            C_beta_arr.push(res.C_beta);
            C_blind_arr.push(res.C_blind);
            pi_eval_arr.push(res.pi_eval);
        }

        let t0 = performance.now();
        sc.verifyEvalProofBatch(C_A_arr, C_L_arr, C_beta_arr, C_blind_arr, pi_eval_arr);
        sc_v1 += (performance.now() - t0);

        for (let i = 0; i < l; i++) {
            let t0_dec = performance.now();
            const res = leader.decideMatch(C_blind_arr[i]);
            t_l += (performance.now() - t0_dec);
            pi_final_arr.push(res.pi_final);
        }

        t0 = performance.now();
        sc.verifyFinalProofBatch(C_blind_arr, pi_final_arr, keyL.pub);
        sc_v2 += (performance.now() - t0);

        hepsi_total += (t_a + sc_v1 + t_l + sc_v2);

        // =====================================
        // COT-PE
        // =====================================
        const resCOT = cotpeEngine.runProtocol(routeA, routeL, 10); // tau_min = 10
        cotpe_p1 += resCOT.latencies.phase1_ms;
        cotpe_p2 += resCOT.latencies.phase2_ms;
        cotpe_p3 += resCOT.latencies.phase3_ms;
        cotpe_p4 += resCOT.latencies.phase4_ms;
        cotpe_p5 += resCOT.latencies.phase5_ms;
        cotpe_total += resCOT.latencies.total_online_ms;
    }

    // Averages
    const avg_hepsi = (hepsi_total / ITERATIONS).toFixed(3);
    const avg_p1 = (cotpe_p1 / ITERATIONS).toFixed(3);
    const avg_p2 = (cotpe_p2 / ITERATIONS).toFixed(3);
    const avg_p3 = (cotpe_p3 / ITERATIONS).toFixed(3);
    const avg_p4 = (cotpe_p4 / ITERATIONS).toFixed(3);
    const avg_p5 = (cotpe_p5 / ITERATIONS).toFixed(3);
    const avg_cotpe = (cotpe_total / ITERATIONS).toFixed(3);

    const row = `${l},${avg_hepsi},${avg_p1},${avg_p2},${avg_p3},${avg_p4},${avg_p5},${avg_cotpe}`;
    console.log(row.replace(/,/g, ' | '));
    csvContent += row + "\n";
}

fs.writeFileSync(csvPath, csvContent, 'utf8');
console.log(`\nBenchmarks completed. Results saved to benchmark_latency.csv`);
