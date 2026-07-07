# Truck Platooning Simulation Runbook

This guide maps the codebase to the 4 paper phases and gives the exact order to run the demo scripts in this repository.

## Important setup note

This project does not use a persistent database. The chain server keeps state in memory through `chain/store/user.store.js`, so restarting `chain/app.js` resets users, encrypted paths, blind paths, and platoon membership.

Also note that there are two naming conventions in the repo:

* `setup/keyGen.js` generates user-scoped files such as `public/user1_auth_pk.json` and `private/user1_auth_sk.json`.
* The demo scripts in `prover/` mostly read shared filenames such as `public/auth_pk.json`, `public/paillier_pk.json`, `private/auth_sk.json`, and `private/paillier_sk.json`.

That means the repository can be run as-is with the shipped artifacts in `public/` and `private/`, but if you regenerate keys from scratch you may need to copy or rename the generated files to the shared filenames expected by the prover scripts.

## 1. Setup Sequence

1. Install dependencies in each module:

```bash
cd chain
npm install

cd ../setup
npm install

cd ../prover
npm install
```

2. Start the chain server first. This is the immutable smart-contract simulation that every other script talks to:

```bash
cd chain
node app.js
```

3. If you want to regenerate cryptographic material, run the setup script in a second terminal:

```bash
cd setup
node keyGen.js
```

4. Confirm the required shared artifacts exist before running the prover scripts:

* `public/auth_pk.json`
* `public/paillier_pk.json`
* `private/auth_sk.json`
* `private/paillier_sk.json`
* `private/path.js`

5. Keep the chain terminal open for the entire run. Every phase 1 and phase 2 script calls the local HTTP API on `http://localhost:3000`.

## 2. Execution Order

Use the numbered scripts below for the closest paper-to-code lifecycle. This is the recommended order for a complete run.

1. Start the chain server:

```bash
cd chain
node app.js
```

2. Register both trucks on-chain:

```bash
cd prover
node 1_registerUsers.js
```

This posts to `POST /register` twice, once for user `1` and once for user `2`.

3. Commit the platoon leader route:

```bash
cd prover
node 2_user1Commit.js
```

This encrypts `private/path.js -> priv_path` and submits the encrypted route to `POST /verify/path`.

4. Commit the applicant route:

```bash
cd prover
node 2b_user2Commit.js
```

This encrypts `priv_path_2` and also submits it to `POST /verify/path`.

5. Run the applicant joining flow:

```bash
cd prover
node 3_user2Join.js
```

This performs two actions in sequence:

* submits the BLS aggregate authentication proof to `POST /verify/auth`
* computes the cross-modulus blind proof payload and submits it to `POST /verify/cBlindPath`

6. Run the leader-side final check and admission decision:

```bash
cd prover
node 4_user1Verify.js
```

This fetches the stored blind path for user `2`, double-blinds and decrypts it locally, then posts the final proof bundle to `POST /verify/finalMatch`.

7. Simulate Phase 3 TA-TGDH key establishment:

```bash
cd prover
node 5_keyEstablishment.js
```

This is a local simulation only. It does not call the chain server; it prints the derived binary-tree Diffie-Hellman session key.

8. Simulate Phase 4 universal dynamic separation:

```bash
cd prover
node 6_platoonFracture.js
```

This is also local-only and prints the departure and repair behavior for a splintering platoon.

### Optional shortcut

If you want a single-script demo for the first three protocol stages, you can also run:

```bash
cd prover
node prover.js
```

That script performs route commitment, BLS authentication, and cBlind matching in one pass. It is useful for quick smoke tests, but the numbered scripts above are better if you want the full paper-mapped flow.

## 3. Codebase Mapping

### Phase 1: Universal Setup and Route Commitment

* `setup/keyGen.js` generates Paillier and BLS key material.
* `chain/routes/user.routes.js` `POST /register` stores the public auth keys and Paillier public key.
* `prover/helpers/path.helper.js` creates encrypted path segments plus the Paillier correctness proofs.
* `chain/routes/verify.routes.js` `POST /verify/path` validates the encrypted route and stores it on success.
* `chain/helpers/paillier.helper.js` performs the per-segment proof checks.
* `chain/routes/user.routes.js` `GET /users/:id/path` lets later phases fetch the committed encrypted route.

### Phase 2: Catching-Up and Cross-Modulus Joining

* `prover/helpers/cBlind_path.helper.js` constructs the applicant-side cross-modulus blind proof payload.
* `chain/routes/verify.routes.js` `POST /verify/auth` validates the aggregate BLS authentication proof.
* `chain/helpers/bls.helper.js` aggregates public keys and verifies the aggregate signature.
* `chain/routes/verify.routes.js` `POST /verify/cBlindPath` checks the blind path equations and stores the blind path on success.
* `chain/helpers/cBlindPaillier.helper.js` recomputes the Fiat-Shamir challenge and verifies the three blind-match equations.
* `prover/helpers/platoon.helper.js` models the leader-side double-blind and honest-decryption proof generation.
* `chain/routes/verify.routes.js` `POST /verify/finalMatch` checks the final decryption and route equality condition.
* `chain/helpers/platoon.helper.js` verifies the final binding proof and decrypted result.

### Phase 3: TA-TGDH Key Establishment

* `chain/helpers/tgdh.helper.js` defines the Diffie-Hellman group parameters and the `TGDHNode` helper.
* `prover/5_keyEstablishment.js` simulates the binary-tree key derivation and prints the root platoon session key.

### Phase 4: Universal Dynamic Separation

* `prover/6_platoonFracture.js` simulates a subtree departure and the remaining-tree repair.
* `chain/helpers/tgdh.helper.js` is reused for the key propagation math.

## 4. Validation Checkpoints

### After `node app.js`

* The terminal should print the server banner and `Running on http://localhost:3000`.
* `GET /` should return `status: "ok"` and `registeredUsers: 0` before registration.

### After `node 1_registerUsers.js`

* The chain terminal should log two registration messages.
* `GET /users` should show two users with `hasPubKey: true`.
* `GET /users/1` and `GET /users/2` should each show `numKeys: 3` because `numberOfCompanies = 3`.

### After `node 2_user1Commit.js`

* `POST /verify/path` should return `verified: true`.
* `GET /users/1/path` should return an `encryptedPath` array.
* The returned `pathLength` should match `private/path.js` for user 1, which is currently 3 segments.
* The chain terminal should log `Path verified and stored for user 1`.

### After `node 2b_user2Commit.js`

* `POST /verify/path` should return `verified: true` for user 2 as well.
* `GET /users/2/path` should return `encryptedPath` and `pathLength: 3`.
* The chain terminal should log `Path verified and stored for user 2`.

### After `node 3_user2Join.js`

* `POST /verify/auth` should return `verified: true` if the BLS aggregate proof matches the registered public keys.
* `POST /verify/cBlindPath` should return `success: true` and `verified: true` if the blind proof equations are valid.
* `GET /users/2/blindPath` should now return the stored blind path array.

### After `node 4_user1Verify.js`

* `POST /verify/finalMatch` should return a result object with `verified` and `matched` fields.
* With the current sample paths in `private/path.js` (`["1","2","5"]` for user 1 and `["1","2","6"]` for user 2), the final route match is expected to fail on the last segment.
* The expected message is `Route mismatch, rejected.`
* This is the checkpoint that distinguishes a mathematically valid proof from a successful route merge.

### After `node 5_keyEstablishment.js`

* The console should print the intermediate pairwise DH derivations and the final root platoon key.
* There is no HTTP response because this script is a local TA-TGDH simulation.

### After `node 6_platoonFracture.js`

* The console should print the departure of the subtree and the repair of the remaining tree.
* The departing subgroup should reuse its internal subtree key with zero extra network overhead.
* The remaining subgroup should show a fresh key derivation for forward secrecy.

## 5. Testing Malicious Behavior

These are the cleanest ways to force a rejection while keeping the rest of the workflow intact.

### A. Submit a fake route `m_fake`

Edit `prover/2_user1Commit.js` or `prover/2b_user2Commit.js` and tamper with the ciphertext or proof before the `fetch` call.

Example: after `const { encryptedPath, proofs } = ...`, change one segment:

```js
encryptedPath[0] = (BigInt(encryptedPath[0]) + 1n).toString();
```

Expected result:

* `POST /verify/path` returns `verified: false`
* the chain does not store the encrypted path for that user

You can also tamper with the proof instead of the ciphertext:

```js
proofs[0].z1 = (BigInt(proofs[0].z1) + 1n).toString();
```

That should fail the Paillier proof check in `chain/helpers/paillier.helper.js`.

### B. Break the cross-modulus ZKP

Edit `prover/3_user2Join.js` after `proverBlindMatch(...)` returns and change one proof field before sending `blindPath` to the chain.

Example:

```js
blindPath[0].proof.e = (BigInt(blindPath[0].proof.e) + 1n).toString();
```

Expected result:

* `POST /verify/cBlindPath` returns `verified: false`
* the server logs one of the blind-match failures, such as `Hash Mismatch` or `Equation X Verification Failed`
* the applicant does not get a stored blind path

If you want to break the proof more directly, mutate `z_alpha`, `z_beta`, `z1`, `z2`, or `z3` by 1.

### C. Force a decryption mismatch

Edit `prover/4_user1Verify.js` before the `fetch("/verify/finalMatch")` call and alter one of the `finalPaths` entries.

Example:

```js
finalPaths[0].m_true = "999";
```

Expected result:

* `POST /verify/finalMatch` returns `verified: false` or `matched: false`
* the chain logs `Deterministic Decryption Verification Failed` if the proof no longer binds
* if only `m_true` is altered, the final admission should fail because the decrypted route no longer matches the expected equality condition

You can also break the binding proof itself:

```js
finalPaths[0].proof.z_plat = (BigInt(finalPaths[0].proof.z_plat) + 1n).toString();
```

That should fail the final Fiat-Shamir binding check in `chain/helpers/platoon.helper.js`.

## Recommended Paper-Mapped Run

If you want the closest match to the 4 theoretical phases, use this order:

1. `chain/app.js`
2. `prover/1_registerUsers.js`
3. `prover/2_user1Commit.js`
4. `prover/2b_user2Commit.js`
5. `prover/3_user2Join.js`
6. `prover/4_user1Verify.js`
7. `prover/5_keyEstablishment.js`
8. `prover/6_platoonFracture.js`

That sequence covers the full route commitment, authentication, cross-modulus joining, TA-TGDH derivation, and platoon fracture lifecycle.
