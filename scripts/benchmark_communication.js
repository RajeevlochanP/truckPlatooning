const fs = require('fs');
const path = require('path');
const Applicant = require('../myPaper/src/core/Applicant');
const Leader = require('../myPaper/src/core/Leader');

function getByteSize(obj) {
    if (typeof obj === 'bigint') {
        let hex = obj.toString(16);
        if (hex.length % 2 !== 0) hex = '0' + hex;
        return hex.length / 2;
    }
    if (typeof obj === 'number' || typeof obj === 'boolean') return 1; // Approx for flags/tiny ints
    if (Array.isArray(obj)) return obj.reduce((sum, item) => sum + getByteSize(item), 0);
    if (obj !== null && typeof obj === 'object') {
        return Object.values(obj).reduce((sum, val) => sum + getByteSize(val), 0);
    }
    return 0;
}

// Convert JSON keys with strings back to BigInts
function parseKeys(obj) {
    if (typeof obj === 'string' && /^[0-9]+$/.test(obj)) {
        return BigInt(obj);
    }
    if (Array.isArray(obj)) {
        return obj.map(parseKeys);
    }
    if (obj !== null && typeof obj === 'object') {
        const result = {};
        for (const [k, v] of Object.entries(obj)) {
            result[k] = parseKeys(v);
        }
        return result;
    }
    return obj;
}

async function runBenchmark() {
    const keysPath = path.join(__dirname, '../myPaper/keys.json');
    if (!fs.existsSync(keysPath)) {
        console.error("keys.json not found at", keysPath);
        process.exit(1);
    }
    
    const keysRaw = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    const keys = parseKeys(keysRaw);

    const applicant = new Applicant(keys.Applicant, keys.Leader.pub);
    const leader = new Leader(keys.Leader, keys.Applicant.pub);

    const w = 100;

    // Run HE-PSI protocol for one waypoint
    const cA = applicant.commitWaypoint(w);
    const cL = leader.commitWaypoint(w);

    const payload_TA_to_SC_Commit = { C_A: cA.C_x, pi_init: cA.pi_init };
    const payload_TL_to_SC_Commit = { C_L: cL.C_x, pi_init: cL.pi_init };
    const payload_SC_to_TA_Fetch = { C_L: cL.C_x };

    const state = applicant.precomputeEval(cA.C_A_inv);
    const evalResult = applicant.evaluateMatch(cA.w, cA.C_x, cA.C_A_inv, cA.r_A_inv, cL.C_x, state);

    const payload_TA_to_SC_Eval = { C_beta: evalResult.C_beta, C_blind: evalResult.C_blind, pi_eval: evalResult.pi_eval };
    const payload_SC_to_TL_Fetch = { C_blind: evalResult.C_blind };

    const decideResult = leader.decideMatch(evalResult.C_blind);
    const payload_TL_to_SC_Final = decideResult.pi_final; // TL sends pi_final

    // Measure Sizes
    const s_TA_to_SC_Commit = getByteSize(payload_TA_to_SC_Commit);
    const s_TL_to_SC_Commit = getByteSize(payload_TL_to_SC_Commit);
    const s_SC_to_TA_Fetch = getByteSize(payload_SC_to_TA_Fetch);
    const s_TA_to_SC_Eval = getByteSize(payload_TA_to_SC_Eval);
    const s_SC_to_TL_Fetch = getByteSize(payload_SC_to_TL_Fetch);
    const s_TL_to_SC_Final = getByteSize(payload_TL_to_SC_Final);

    const he_total_bytes = s_TA_to_SC_Commit + s_TL_to_SC_Commit + s_SC_to_TA_Fetch + 
                           s_TA_to_SC_Eval + s_SC_to_TL_Fetch + s_TL_to_SC_Final;

    const tarot_cui_to_cuj_bytes = 4096;
    const tarot_cuj_to_cui_bytes = 4096;
    const tarot_total_bytes = tarot_cui_to_cuj_bytes + tarot_cuj_to_cui_bytes;

    const pathLengths = [10, 20, 30, 40, 50];
    const csvPath = path.join(__dirname, 'benchmark_communication.csv');

    const csvHeader = "PathLength(l),HE_TA_to_SC_KB,HE_TL_to_SC_KB,HE_SC_to_TA_KB,HE_TA_to_SC_Eval_KB,HE_SC_to_TL_KB,HE_TL_to_SC_Final_KB,HE_Total_KB,TAROT_CUi_to_CUj_KB,TAROT_CUj_to_CUi_KB,TAROT_Total_KB";
    let csvContent = csvHeader + "\n";
    console.log(csvHeader);

    for (const l of pathLengths) {
        const kb = (bytes) => ((bytes * l) / 1024).toFixed(2);
        
        const row = [
            l,
            kb(s_TA_to_SC_Commit),
            kb(s_TL_to_SC_Commit),
            kb(s_SC_to_TA_Fetch),
            kb(s_TA_to_SC_Eval),
            kb(s_SC_to_TL_Fetch),
            kb(s_TL_to_SC_Final),
            kb(he_total_bytes),
            kb(tarot_cui_to_cuj_bytes),
            kb(tarot_cuj_to_cui_bytes),
            kb(tarot_total_bytes)
        ].join(",");

        console.log(row);
        csvContent += row + "\n";
    }

    fs.writeFileSync(csvPath, csvContent, 'utf8');
    console.log(`\nCommunication benchmarks completed. Results saved to benchmark_communication.csv`);
}

runBenchmark();
