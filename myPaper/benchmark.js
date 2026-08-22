const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');

const Applicant = require('./src/core/Applicant');
const Leader = require('./src/core/Leader');
const SmartContract = require('./src/core/SmartContract');

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

function runBenchmark() {
    const keysPath = path.join(__dirname, 'keys.json');
    
    // NEW: Define the output path for the CSV file
    const outputPath = path.join(__dirname, 'benchmark_results.csv');
    
    if (!fs.existsSync(keysPath)) {
        console.error("keys.json not found! Run 'node scripts/generateKeys.js' first.");
        process.exit(1);
    }
    
    // File I/O and key parsing OUTSIDE timing blocks
    const keysRaw = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    const keys = parseBigInts(keysRaw);
    
    const keyA = keys.Applicant;
    const keyL = keys.Leader;
    
    const applicant = new Applicant(keyA, keyL.pub);
    const leader = new Leader(keyL, keyA.pub);
    const sc = new SmartContract(keyA.pub, keyL.pub);
    
    const pathLengths = [10, 20, 30, 40, 50];
    
    // NEW: Initialize a string to hold the CSV content
    const csvHeader = "PathLength(l),T_A_Gen_ms,SC_Verify_ms,T_L_Dec_ms,Total_ms";
    let csvContent = csvHeader + "\n";
    console.log(csvHeader);
    
    for (const l of pathLengths) {
        // Generate Phase 1 initial route commitments OUTSIDE timing block
        const routeA = Array.from({length: l}, (_, i) => BigInt(i + 100));
        const routeL = Array.from({length: l}, (_, i) => BigInt(i + 100)); // matching route
        
        const commsA = routeA.map(w => applicant.commitWaypoint(w));
        const commsL = routeL.map(w => leader.commitWaypoint(w));
        
        // Precompute offline states
        const statesA = commsA.map(cA => applicant.precomputeEval(cA.C_A_inv));
        
        let t_a_ms = 0;
        let sc_verify_ms = 0;
        let t_l_dec_ms = 0;
        
        let C_A_arr = [], C_L_arr = [], C_beta_arr = [], C_blind_arr = [], pi_eval_arr = [], pi_final_arr = [];

        // Loop 1 (Applicant Generation)
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

        // Batch Verify 1
        let t0 = performance.now();
        const isValid = sc.verifyEvalProofBatch(C_A_arr, C_L_arr, C_beta_arr, C_blind_arr, pi_eval_arr);
        let t1 = performance.now();
        sc_verify_ms += (t1 - t0);
        
        if (!isValid) {
            console.error("Smart Contract Verification Failed for batch!");
            process.exit(1);
        }

        // Loop 2 (Leader Decrypt)
        for (let i = 0; i < l; i++) {
            let t0 = performance.now();
            const { isMatch, m_true, pi_final } = leader.decideMatch(C_blind_arr[i]);
            let t1 = performance.now();
            t_l_dec_ms += (t1 - t0);
            
            if (!isMatch) {
                console.error("Match failed for identical waypoint!");
                process.exit(1);
            }
            
            pi_final_arr.push(pi_final);
        }

        // Batch Verify 2
        t0 = performance.now();
        const isFinalValid = sc.verifyFinalProofBatch(C_blind_arr, pi_final_arr, keyL.pub);
        t1 = performance.now();
        sc_verify_ms += (t1 - t0);
        
        if (!isFinalValid) {
            console.error("Smart Contract Verification of Final Proof Failed for batch!");
            process.exit(1);
        }
        
        const total_ms = t_a_ms + sc_verify_ms + t_l_dec_ms;
        
        // NEW: Format the result row, print it, and append it to the CSV string
        const resultRow = `${l},${t_a_ms.toFixed(3)},${sc_verify_ms.toFixed(3)},${t_l_dec_ms.toFixed(3)},${total_ms.toFixed(3)}`;
        console.log(resultRow);
        csvContent += resultRow + "\n";
    }
    
    // NEW: Write the accumulated CSV string to the file synchronously
    fs.writeFileSync(outputPath, csvContent, 'utf8');
    console.log(`\n✅ Benchmark complete! Results saved to ${outputPath}`);
}

runBenchmark();