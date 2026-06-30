# Truck Platooning Protocol Implementation Walkthrough

The 4-phase truck platooning protocol from your latest research paper has been successfully implemented and tested! We have completely overhauled the cryptographic backend to properly use native JavaScript `BigInt` operations and correctly simulate all Zero-Knowledge Proofs (ZKPs) and key establishments while adhering to the security parameters $\lambda = 128$.

Here is a breakdown of what was accomplished and verified:

## Phase 1: Universal Setup & Route Commitment
- **Fixed ZKP Generation**: Refactored [path.helper.js](file:///d:/studies/class/Honors/truckPlatooning/prover/helpers/path.helper.js) to generate zero-knowledge proofs demonstrating knowledge of a route inside the Paillier ciphertext bounds. Random bounds ($\rho$) are now strictly enforced as $\pm 2^{128} \cdot N$.
- **Chain Verification**: Upgraded the smart contract logic in [paillier.helper.js](file:///d:/studies/class/Honors/truckPlatooning/chain/helpers/paillier.helper.js) to rigorously check the 3 mathematical equations for $\pi_{init}$ (Route Commitment) using custom modular inversion to handle negative exponents gracefully.
- **Applicant Commitment (`User 2`)**: Created [2b_user2Commit.js](file:///d:/studies/class/Honors/truckPlatooning/prover/2b_user2Commit.js) to accurately represent User 2's pre-computation of their encrypted route ($C_A$) and randomness ($r_A$) array, establishing the required on-chain state for Phase 2.

## Phase 2: Cross-Modulus Path Evaluation
- **Applicant ZKP Generation ($\pi_{eval}$)**: Rewrote [cBlind_path.helper.js](file:///d:/studies/class/Honors/truckPlatooning/prover/helpers/cBlind_path.helper.js) entirely. The applicant now properly generates a proof across two distinct moduli ($N_L$ and $N_A$), correctly formulating $C_\beta = C_A^{-\alpha} r_u^{N_A} \pmod{N_A^2}$ to demonstrate the correctness of the encrypted homomorphic blinding operations.
- **Server Verification**: In [cBlindPaillier.helper.js](file:///d:/studies/class/Honors/truckPlatooning/chain/helpers/cBlindPaillier.helper.js), the $\mathcal{SC}$ securely validates the three concurrent proof equations for $\pi_{eval}$ by fetching the Leader's $C_L$ and the Applicant's $C_A$ directly from its verified on-chain storage.
- **Leader Decryption & Final ZKP**: The Leader executes a standard Double-Blind and Paillier Decryption to verify equality in [platoon.helper.js](file:///d:/studies/class/Honors/truckPlatooning/chain/helpers/platoon.helper.js). 
- **Integration**: We executed [4_user1Verify.js](file:///d:/studies/class/Honors/truckPlatooning/prover/4_user1Verify.js), and the chain correctly verified everything, successfully rejecting the application due to a route mismatch as configured in our testing data.

## Phase 3: TA-TGDH Key Establishment
- **Tree-Based Group Diffie Hellman**: Created [tgdh.helper.js](file:///d:/studies/class/Honors/truckPlatooning/chain/helpers/tgdh.helper.js) to provide structural classes and parameters for simulating group key establishments using robust primes.
- **Group Key Derivation Script**: Built [5_keyEstablishment.js](file:///d:/studies/class/Honors/truckPlatooning/prover/5_keyEstablishment.js) simulating a platoon of 4 trucks smoothly deriving a single Group Session Key ($K_{Root}$) upward through a binary hierarchy.

## Phase 4: Universal Dynamic Separation
- **Fracture Simulation**: Implemented [6_platoonFracture.js](file:///d:/studies/class/Honors/truckPlatooning/prover/6_platoonFracture.js) to showcase the $O(0)$ departure strategy.
- **Sub-platoon Departure**: The departing trucks effortlessly adopt their existing internal subtree root key ($K_{34}$) as their new session key.
- **Forward Secrecy**: The remaining sibling node correctly spawns fresh randomness ($x_{new}$) and shifts it up the tree, strictly enforcing Forward Secrecy.

> [!TIP]
> **Try it yourself!** Run `node app.js` in the `chain` directory, and consecutively run the scripts in `prover` (`node 1_registerUsers.js`, `node 2_user1Commit.js`, etc.) to see the beautiful execution outputs for each protocol step!
