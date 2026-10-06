#!/usr/bin/env python3
import subprocess
import os
import sys
import numpy as np
import pandas as pd

# Path to the compiled binary
BINARY_PATH = "./build/ppi_platoon"
RAW_CSV = "ppi_benchmark_results.csv"
SUMMARY_CSV = "ppi_paper_summary.csv"

# Experimental Design
# 1. Trajectory length scaling (primary independent variable)
N_VALUES = [100, 250, 500, 750, 1000, 1500, 2000]

# 2. Alphabet size (|Sigma|: possible discrete waypoint/maneuver symbols per epoch)
SIGMA_SIZE = 5

# 3. Minimum threshold tau_min
TAU_MIN = 4

# 4. Trials per configuration
NUM_WARMUPS = 2
NUM_TRIALS = 10

def run_single(n, sigma, tau, div_idx):
    cmd = [BINARY_PATH, str(n), str(sigma), str(tau), str(div_idx)]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        print(f"Error running configuration n={n}: {res.stderr}", file=sys.stderr)
        return False
    return True

def main():
    if not os.path.exists(BINARY_PATH):
        print(f"Executable not found at {BINARY_PATH}. Compile first with cmake.", file=sys.stderr)
        sys.exit(1)

    # Clear previous raw CSV to ensure clean trial mapping
    if os.path.exists(RAW_CSV):
        os.remove(RAW_CSV)

    summary_records = []

    print(f"{'='*70}")
    print(f"Starting PPI Empirical Evaluation ({NUM_TRIALS} trials per configuration)")
    print(f"{'='*70}\n")

    for n in N_VALUES:
        # Full match scenario evaluates worst-case online computation across the full length
        div_idx = n 

        print(f"[Running] n = {n:<5} | sigma = {SIGMA_SIZE} | tau_min = {TAU_MIN} ... ", end="", flush=True)

        # Warmup iterations (discarded to stabilize CPU frequency scaling)
        for _ in range(NUM_WARMUPS):
            run_single(n, SIGMA_SIZE, TAU_MIN, div_idx)

        # Measured trials
        start_row_idx = 0
        if os.path.exists(RAW_CSV):
            start_row_idx = len(pd.read_csv(RAW_CSV))

        for _ in range(NUM_TRIALS):
            success = run_single(n, SIGMA_SIZE, TAU_MIN, div_idx)
            if not success:
                break

        # Read back latest trials from CSV
        df_raw = pd.read_csv(RAW_CSV)
        trial_data = df_raw.iloc[start_row_idx:]

        # Compute mean and standard deviations
        record = {
            "n": n,
            "offline_commit_mean": trial_data["offline_commit_ms"].mean(),
            "offline_commit_std":  trial_data["offline_commit_ms"].std(),
            "online_ot_mean":      trial_data["totalOnlineOT"].mean(),
            "online_ot_std":       trial_data["totalOnlineOT"].std(),
            "payload_gen_mean":    trial_data["payload_gen_ms"].mean(),
            "payload_gen_std":     trial_data["payload_gen_ms"].std(),
            "prefix_eval_mean":    trial_data["prefix_eval_ms"].mean(),
            "prefix_eval_std":     trial_data["prefix_eval_ms"].std(),
            "total_online_mean":   trial_data["totalOnlineTime"].mean(),
            "total_online_std":    trial_data["totalOnlineTime"].std(),
            "total_time_mean":     trial_data["totalTime"].mean(),
            "total_time_std":      trial_data["totalTime"].std(),
        }
        summary_records.append(record)
        print(f"Done. (Online Rendezvous: {record['total_online_mean']:.2f} ± {record['total_online_std']:.2f} ms)")

    summary_df = pd.DataFrame(summary_records)
    summary_df.to_csv(SUMMARY_CSV, index=False)

    print(f"\n{'='*70}")
    print(f"Summary Results Written to: {SUMMARY_CSV}")
    print(f"{'='*70}\n")

    # Display console summary table
    print(f"{'n':<6} | {'Offline Commit (ms)':<20} | {'Online OT (ms)':<16} | {'Prefix Eval (ms)':<18} | {'Total Online (ms)':<20}")
    print("-" * 88)
    for _, r in summary_df.iterrows():
        print(f"{int(r['n']):<6} | "
              f"{r['offline_commit_mean']:>6.2f} ± {r['offline_commit_std']:<6.2f}     | "
              f"{r['online_ot_mean']:>6.2f} ± {r['online_ot_std']:<5.2f}   | "
              f"{r['prefix_eval_mean']:>6.2f} ± {r['prefix_eval_std']:<6.2f}   | "
              f"{r['total_online_mean']:>6.2f} ± {r['total_online_std']:<6.2f}")

    # Generate LaTeX tabular snippet
    print("\n" + "="*30 + " LaTeX Code Snippet " + "="*30)
    print("\\begin{table}[t]")
    print("\\centering")
    print("\\caption{Empirical Computation Latency of the Proposed PPI Protocol ($|\\Sigma|=5$, $\\tau_{\\min}=4$)}")
    print("\\label{tab:ppi_benchmarks}")
    print("\\begin{tabular}{rccccc}")
    print("\\hline")
    print("$n$ & Offline Commit (ms) & Online OT (ms) & Payload Gen (ms) & Prefix Eval (ms) & Total Online (ms) \\\\")
    print("\\hline")
    for _, r in summary_df.iterrows():
        print(f"{int(r['n'])} & "
              f"${r['offline_commit_mean']:.2f} \\pm {r['offline_commit_std']:.2f}$ & "
              f"${r['online_ot_mean']:.2f} \\pm {r['online_ot_std']:.2f}$ & "
              f"${r['payload_gen_mean']:.2f} \\pm {r['payload_gen_std']:.2f}$ & "
              f"${r['prefix_eval_mean']:.2f} \\pm {r['prefix_eval_std']:.2f}$ & "
              f"\\textbf{{{r['total_online_mean']:.2f} $\\pm$ {r['total_online_std']:.2f}}} \\\\")
    print("\\hline")
    print("\\end{tabular}")
    print("\\end{table}")

if __name__ == "__main__":
    main()