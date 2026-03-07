# Truck Platooning — Aggregated Zero-Knowledge Proof & Blockchain-Empowered Authentication

## Base Paper

This implementation is based on:

> **Aggregated Zero-Knowledge Proof and Blockchain-Empowered Authentication for Autonomous Truck Platooning**
> *(Aggregated_Zero-Knowledge_Proof_and_Blockchain-Empowered_Authentication_for_Autonomous_Truck_Platooning.pdf)*

The system enables privacy-preserving authentication and path verification for autonomous truck platoons using:

- **Paillier Homomorphic Encryption** — encrypts private truck paths so the chain can verify without decryption.
- **BLS Aggregate Signatures** — authenticates trucks via aggregated BLS12-381 proofs from multiple fleet company keys.
- **Zero-Knowledge Proofs (ZoKrates)** — proves path validity on a public graph without revealing the private path.
- **CBlind Paillier Protocol** — blindly matches an incoming truck's path against a stored encrypted platoon path on-chain.

---

## Project Structure

| Directory | Purpose |
|-----------|---------|
| `setup/` | Key generation (Paillier + BLS) and user registration on the chain |
| `chain/` | Express.js verification server (simulated blockchain node) |
| `prover/` | Truck-side prover: encrypts path, generates BLS auth proof, runs CBlind match |
| `public/` | Shared public artifacts (keys, proofs, ZoKrates circuit, graph) |
| `private/` | Local secrets (private keys, witness, private paths) |

---

## Prerequisites

- **Node.js** ≥ 18 (ES module support required)

---

## Installation

Install dependencies in each module:

```bash
cd setup
npm install

cd ../chain
npm install

cd ../prover
npm install
```

---

## How to Run

### 1. Start the Chain (Verification Server)

```bash
cd chain
node app.js
```

The server starts on `http://localhost:3000` by default. It exposes the following endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Health check & endpoint listing |
| POST | `/register` | Register a user with auth public keys & Paillier public key |
| GET | `/users` | List all registered users |
| GET | `/users/:id` | Get user details |
| GET | `/users/:id/path` | Get user's stored encrypted path |
| DELETE | `/users/:id` | Unregister a user |
| POST | `/verify/path` | Verify Paillier encrypted path proofs & store path |
| POST | `/verify/auth` | Verify aggregated BLS authentication proof |
| POST | `/verify/cBlindPath` | Verify blind path match proofs |

### 2. Run Key Generation & Registration (Setup)

With the chain server running, open a **new terminal**:

```bash
cd setup
node keyGen.js
```

This will:
1. Generate a **Paillier keypair** (3072-bit).
2. Generate **BLS12-381 auth keypairs** for 3 fleet companies.
3. Register the truck (public keys) on the chain via `POST /register`.
4. Save keys locally to `public/` and `private/`.

### 3. Run the Prover (Truck Side)

```bash
cd prover
node prover.js
```

This executes the full protocol in sequence:

1. **Path Encryption** — Encrypts the truck's private path using Paillier and generates correctness proofs, then sends them to the chain (`POST /verify/path`).
2. **BLS Authentication** — Generates per-company BLS proofs on a one-time message, aggregates them, and sends to the chain for pairing-based verification (`POST /verify/auth`).
3. **CBlind Path Matching** — Fetches the stored encrypted platoon path from the chain, computes blinded difference ciphertexts with random masks, and submits them for on-chain blind match verification (`POST /verify/cBlindPath`).

---

## Configuration

- **`setup/parameters.js`** — Number of fleet companies (`numberOfCompanies`) and Paillier key bit length (`paillierBitLength`).
- **`prover/parameters.js`** — Same parameters mirrored for the prover.
- **`chain/config/index.js`** — Server port and minimum path match threshold.
- **`private/path.js`** — Private paths used by the prover (`priv_path` for the platoon leader, `priv_path_2` for the joining truck).

---

## Protocol Flow (Summary)

```
┌──────────┐         ┌───────────────┐         ┌──────────┐
│  Setup   │         │  Chain Server │         │  Prover  │
│ (keyGen) │         │  (Verifier)   │         │  (Truck) │
└────┬─────┘         └───────┬───────┘         └────┬─────┘
     │  1. Generate keys     │                      │
     │  2. POST /register ──►│                      │
     │       (authPKs,       │                      │
     │        paillierPK)    │                      │
     │                       │◄── 3. POST /verify/path
     │                       │    (encrypted path +  │
     │                       │     Paillier proofs)  │
     │                       │                      │
     │                       │◄── 4. POST /verify/auth
     │                       │    (aggregated BLS    │
     │                       │     proof Ω_agg)      │
     │                       │                      │
     │                       │◄── 5. POST /verify/cBlindPath
     │                       │    (blinded ciphertexts│
     │                       │     for path match)   │
     └───────────────────────┴──────────────────────┘
```
