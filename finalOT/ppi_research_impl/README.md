# Research PPI implementation

This version removes the simulated OT layer from the supplied prototype. The
private-prefix construction is implemented directly, while malicious 1-out-of-
N random OT is instantiated with libOTe's concrete OOS implementation.

## What is implemented here

- trajectory commitments registered with a local Smart Contract ledger;
- single-use evaluation of a registered session commitment;
- malicious 1-out-of-N random OT through libOTe OOS;
- real base-OT generation handled by libOTe;
- real OOS correction transfer and malicious consistency check handled by libOTe;
- stateful hash-chain payload construction;
- commitment/tag/equality verification;
- exact longest-common-prefix output;
- minimum-prefix eligibility decision;
- local aggregate-payload communication abstraction.

The Smart Contract and application payload channel are intentionally local
abstractions. The cryptographic OT channel is the actual libOTe/coproto channel;
there is no hand-written or simulated OT implementation in `ppi_platoon.cpp`.

## Requirements

- C++20 compiler
- CMake >= 3.20
- OpenSSL development libraries
- libOTe built with OOS enabled

The current libOTe API exposes the NCO malicious-OT lifecycle used here:
`configure`, `genBaseOts`, `init`, `encode`, `recvCorrection`/`sendCorrection`,
and `check`. The CMake file auto-detects the concrete OOS sender/receiver
classes shipped by the installed libOTe revision so that the application layer
does not depend on a hard-coded concrete class name.

## Build libOTe

From a libOTe checkout, use the project's build script with OOS enabled. A
common current build is:

```bash
python3 build.py --all --sodium --install
```

Keep the installation prefix for the PPI build.

## Build this project

```bash
cmake -S . -B build -DCMAKE_PREFIX_PATH=/path/to/libOTe/install
cmake --build build -j
```

If the package is installed system-wide, `CMAKE_PREFIX_PATH` may be omitted.

If a particular libOTe revision does not expose the concrete OOS class/header
through the exported include directories, CMake supports these explicit
variables:

```text
PPI_OOS_SENDER_CLASS
PPI_OOS_RECEIVER_CLASS
PPI_OOS_SENDER_HEADER
PPI_OOS_RECEIVER_HEADER
```

## Run

Defaults:

```bash
./build/ppi_platoon
```

Or explicitly choose:

```bash
./build/ppi_platoon 10 5 4 6
```

Arguments:

```text
n                  trajectory length
sigma_size         alphabet cardinality (>= 2)
tau_min            minimum eligible prefix length
divergence_index   first index (0-based) where applicant diverges; n means no divergence
```

The supplied code intentionally keeps the Smart Contract and application
payload transport local so the cryptographic PPI implementation can be
benchmarked without deploying a blockchain or network service. The libOTe OOS
protocol itself is executed as a real cryptographic protocol.

## Research-use note

The source was syntax-checked locally against a mock of the verified libOTe NCO
API because the exact libOTe source checkout is not available in this runtime.
The final build must therefore be performed against the target libOTe revision
that you intend to cite and benchmark. Do not report experimental measurements
until that real build has been compiled and run successfully.
