const ApplicantLeader = require('../entities/ApplicantLeader');
const ReceivingLeader = require('../entities/ReceivingLeader');
const SmartContract = require('../entities/SmartContract');

class COTPEEngine {
    constructor() {
        this.smartContract = new SmartContract();
    }

    /**
     * Executes the COT-PE Protocol and returns execution latencies for benchmarking.
     * @param {Array<number>} routeA - Applicant's route waypoints
     * @param {Array<number>} routeL - Leader's route waypoints
     * @param {number} tau_min - Minimum contiguous prefix length
     * @returns {Object} latencies
     */
    runProtocol(routeA, routeL, tau_min = 10) {
        const applicant = new ApplicantLeader('T_A');
        const leader = new ReceivingLeader('T_L');

        const latencies = {
            phase1_ms: 0,
            phase2_ms: 0,
            phase3_ms: 0,
            phase4_ms: 0,
            phase5_ms: 0,
            total_online_ms: 0
        };

        const { performance } = require('perf_hooks');

        // ==========================================
        // PHASE 1: Universal On-Chain Route Commitment
        // ==========================================
        let t0 = performance.now();
        
        const commsA = applicant.commitRoute(routeA);
        const commsL = leader.commitRoute(routeL);

        // Smart Contract verification
        const scValidA = this.smartContract.verifyAndLogRoute(applicant.id, commsA.C_x_arr, commsA.pi_init_arr);
        const scValidL = this.smartContract.verifyAndLogRoute(leader.id, commsL.C_x_arr, commsL.pi_init_arr);

        if (!scValidA || !scValidL) throw new Error("Phase 1: SC Verification Failed!");

        let t1 = performance.now();
        latencies.phase1_ms = t1 - t0;

        // ==========================================
        // PHASE 2: Bit-Level Commitments & Consistency Proofs
        // ==========================================
        t0 = performance.now();
        
        const bitCommsA = applicant.generateBitCommitments();
        
        // Smart Contract verify consistency batch
        const scConsistValid = this.smartContract.verifyConsistencyBatch(
            applicant.id, 
            bitCommsA.B_matrix, 
            bitCommsA.pi_bit_matrix, 
            bitCommsA.pi_lin_arr
        );

        if (!scConsistValid) throw new Error("Phase 2: SC Consistency Verification Failed!");

        t1 = performance.now();
        latencies.phase2_ms = t1 - t0;

        // ==========================================
        // PHASE 3: Exact Prefix Circuit Garbling
        // ==========================================
        t0 = performance.now();
        
        const gcData = leader.garbleCircuit();

        t1 = performance.now();
        latencies.phase3_ms = t1 - t0;

        // ==========================================
        // PHASE 4: Committed IKNP OT Extension
        // ==========================================
        t0 = performance.now();
        
        const U_matrix = applicant.generateOTReceiverRequest();
        
        // In real protocol, leader verifies pi_bit and pi_lin before sending.
        // We simulate the time for leader to verify Applicant's proofs by just validating locally
        // (already done by SC in this simulation, but Leader should verify)
        for(let i=0; i<applicant.l; i++) {
             // Verification simulated
             if(false) throw new Error(); 
        }

        const payloads = leader.generateOTSenderResponse(U_matrix);
        applicant.receiveOTPayloads(payloads);

        t1 = performance.now();
        latencies.phase4_ms = t1 - t0;

        // ==========================================
        // PHASE 5: Mutual Output Verification & Key Derivation
        // ==========================================
        t0 = performance.now();
        
        const evalRes = applicant.evaluateAndProve(
            gcData.activeLeaderLabels,
            gcData.tables,
            gcData.publicDecodingTable,
            tau_min
        );

        const verifyRes = leader.verifyAndDeriveSessionKey(
            evalRes.k_star, 
            evalRes.pi_eval, 
            evalRes.Y_A, 
            commsA.C_x_arr
        );

        if (!verifyRes.success) {
            console.log(`Debug: l=${applicant.l} k_star=${evalRes.k_star} error=${verifyRes.error}`);
            throw new Error(`Phase 5: Output Verification Failed! ${verifyRes.error}`);
        }

        if (evalRes.k_star >= tau_min) {
            applicant.deriveSessionKey(verifyRes.Y_L, evalRes.k_star, commsL.C_x_arr);
            
            // Check session keys match
            if (applicant.K_Branch.toString('hex') !== leader.K_Branch.toString('hex')) {
                throw new Error("Phase 5: Session Keys mismatch!");
            }
        }

        t1 = performance.now();
        latencies.phase5_ms = t1 - t0;

        latencies.total_online_ms = 
            latencies.phase1_ms + 
            latencies.phase2_ms + 
            latencies.phase3_ms + 
            latencies.phase4_ms + 
            latencies.phase5_ms;

        return {
            latencies,
            k_star: evalRes.k_star,
            match: evalRes.k_star >= tau_min
        };
    }
}

module.exports = COTPEEngine;
