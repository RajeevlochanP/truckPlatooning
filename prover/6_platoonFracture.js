import { TGDHNode, randDHSecret, DH_G, DH_P, modPow } from "../chain/helpers/tgdh.helper.js";

console.log("\n--- Phase 4: Universal Dynamic Separation (Platoon Fracture) ---");

// 1. Initial State: Platoon of 4
const t1 = new TGDHNode("T1", true); t1.setPrivateKey(randDHSecret());
const t2 = new TGDHNode("T2", true); t2.setPrivateKey(randDHSecret());
const t3 = new TGDHNode("T3", true); t3.setPrivateKey(randDHSecret());
const t4 = new TGDHNode("T4", true); t4.setPrivateKey(randDHSecret());

const node12 = new TGDHNode("T1-T2"); node12.left = t1; node12.right = t2; node12.computeFromChildren();
const node34 = new TGDHNode("T3-T4"); node34.left = t3; node34.right = t4; node34.computeFromChildren();

const root = new TGDHNode("Root"); root.left = node12; root.right = node34; root.computeFromChildren();

console.log(`[+] Initial Platoon Key (K_Root): ${root.privateKey.toString(16).substring(0, 32)}...`);

// 2. FRACTURE EVENT: T3 and T4 (Subtree node34) depart the platoon
console.log(`\n[!] Fracture Event: T3 and T4 are leaving the platoon!`);

// Departing Sub-platoon Action (0 Operations)
console.log(`\n--- Departing Sub-Platoon (T3, T4) ---`);
console.log(`[+] The Server severs the tree.`);
console.log(`[+] T3 and T4 instantly promote their internal subtree root (K_34) to their new session key.`);
console.log(`[+] Departing Platoon Key: ${node34.privateKey.toString(16).substring(0, 32)}... (0 operations)`);

// Remaining Platoon Action (Re-establishing Forward Secrecy)
console.log(`\n--- Remaining Platoon (T1, T2) ---`);
console.log(`[+] Node12 (T1-T2) acts as the sibling of the departed subtree.`);
console.log(`[+] Node12 generates a fresh random secret (x_new) to ensure Forward Secrecy.`);
node12.setPrivateKey(randDHSecret()); // Fresh x_new

console.log(`[+] Node12 uploads new public key (y_new) to the Server.`);
// If there were more levels, node12 would recursively recompute upward. 
// Since node12 is now the root of the remaining platoon, it becomes the new session key.
console.log(`\n=== FORWARD SECRECY RE-ESTABLISHED ===`);
console.log(`New Remaining Platoon Key: ${node12.privateKey.toString(16).substring(0, 32)}...`);
console.log(`======================================\n`);
