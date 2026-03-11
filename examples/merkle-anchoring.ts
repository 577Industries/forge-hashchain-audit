/**
 * Merkle anchoring example.
 * Run: npx tsx examples/merkle-anchoring.ts
 */

import { AuditLedger, generateKeyPair, InMemoryStorage } from "../src/index.js";

const keys = generateKeyPair();
const storage = new InMemoryStorage();
const ledger = new AuditLedger({ storage, privateKey: keys.privateKey });

console.log("=== Hash-Chain Audit: Merkle Anchoring ===\n");

// Append 10 entries
for (let i = 1; i <= 10; i++) {
  await ledger.append(`action.${i}`, `actor-${i % 3}`, {
    entityType: "record",
    entityId: `rec-${i}`,
    details: { sequence: i },
  });
}
console.log("Appended 10 signed entries.\n");

// Create a Merkle anchor
const anchor = await ledger.createAnchor();
console.log("Merkle anchor created:");
console.log(`  Root: ${anchor.merkleRoot.slice(0, 16)}...`);
console.log(`  Entries: ${anchor.entryCount}`);
console.log(`  Signed: ${anchor.signature ? "yes" : "no"}\n`);

// Verify the anchor
const result1 = await ledger.verifyAnchor(anchor);
console.log(`Anchor verification: ${result1.valid ? "VALID" : "INVALID"}\n`);

// Tamper with an entry
console.log("Tampering with entry #5...\n");
const entries = storage._getEntries();
entries[4] = { ...entries[4], entryHash: "tampered_hash_value" };

// Verify again
const result2 = await ledger.verifyAnchor(anchor);
console.log(`Anchor verification: ${result2.valid ? "VALID" : "INVALID"}`);
if (!result2.valid) {
  console.log(`  Reason: ${result2.reason}`);
}
