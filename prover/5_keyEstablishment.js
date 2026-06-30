import { TGDHNode, randDHSecret, DH_G, DH_P, modPow } from "../chain/helpers/tgdh.helper.js";

console.log("\n--- Phase 3: TA-TGDH Key Establishment (Platoon of 4) ---");

// 1. Initialize 4 leaf nodes representing Trucks (OBUs)
const t1 = new TGDHNode("T1", true);
const t2 = new TGDHNode("T2", true);
const t3 = new TGDHNode("T3", true);
const t4 = new TGDHNode("T4", true);

t1.setPrivateKey(randDHSecret());
t2.setPrivateKey(randDHSecret());
t3.setPrivateKey(randDHSecret());
t4.setPrivateKey(randDHSecret());

console.log(`[+] T1 Public Key Y_1 generated`);
console.log(`[+] T2 Public Key Y_2 generated`);
console.log(`[+] T3 Public Key Y_3 generated`);
console.log(`[+] T4 Public Key Y_4 generated`);

// 2. Bracket Derivation Level 1: Pair up adjacent trucks
console.log("\n[Bracket Derivation] Level 1 (Sibling Pairs)");
const node12 = new TGDHNode("T1-T2");
node12.left = t1;
node12.right = t2;
const Y12 = node12.computeFromChildren();
console.log(`[+] T1 and T2 executed DH -> derived K_12. Uploaded Y_12`);

const node34 = new TGDHNode("T3-T4");
node34.left = t3;
node34.right = t4;
const Y34 = node34.computeFromChildren();
console.log(`[+] T3 and T4 executed DH -> derived K_34. Uploaded Y_34`);

// 3. Bracket Derivation Level 2 (Root Key)
console.log("\n[Bracket Derivation] Level 2 (Root Key)");
const root = new TGDHNode("Root (Platoon Key)");
root.left = node12;
root.right = node34;
const Y_root = root.computeFromChildren();

console.log(`[+] Node_12 and Node_34 executed DH -> derived Platoon Session Key`);
console.log(`\n=== FINAL SESSION KEY ESTABLISHED ===`);
console.log(`Platoon Key (K_Root): ${root.privateKey.toString(16).substring(0, 32)}...`);
console.log(`=====================================\n`);
