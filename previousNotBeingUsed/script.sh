#!/bin/bash
set -euo pipefail

echo "Compiling ZK program..."
node compilation.js

echo "Setting up trusted setup..."
node setup.js

echo "Generating proof as prover..."
node prover.js

echo "Verifying proof as verifier..."
node verifier.js

echo "Done."
