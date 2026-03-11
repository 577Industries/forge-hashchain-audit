/**
 * Tamper detection example.
 * Run: npx tsx examples/tamper-detection.ts
 */

import { AuditLedger, generateKeyPair, InMemoryStorage } from "../src/index.js";

const keys = generateKeyPair();
const storage = new InMemoryStorage();
const ledger = new AuditLedger({ storage, privateKey: keys.privateKey });

console.log("=== Hash-Chain Audit: Tamper Detection ===\n");

// Append 5 audit entries
await ledger.append("user.created", "admin@company.com", {
  entityType: "user",
  entityId: "usr-001",
  details: { email: "alice@example.com", role: "analyst" },
});
await ledger.append("report.generated", "system", {
  entityType: "report",
  entityId: "rpt-042",
});
await ledger.append("data.exported", "alice@example.com", {
  entityType: "dataset",
  entityId: "ds-007",
  details: { format: "csv", rows: 15000 },
});
await ledger.append("config.changed", "admin@company.com", {
  entityType: "setting",
  entityId: "retention-policy",
  details: { from: "90d", to: "180d" },
});
await ledger.append("user.login", "alice@example.com");

console.log("Appended 5 signed audit entries.\n");

// Verify — should be valid
const result1 = await ledger.verify();
console.log(`Chain verification: ${result1.valid ? "VALID" : "INVALID"} (${result1.checked} entries checked)`);

// Now tamper with entry #3
console.log("\nTampering with entry #3 (changing actor)...\n");
const entries = storage._getEntries();
entries[2] = { ...entries[2], actor: "ATTACKER" };

// Verify again — should detect tampering
const result2 = await ledger.verify();
console.log(`Chain verification: ${result2.valid ? "VALID" : "INVALID"}`);
if (!result2.valid) {
  console.log(`  Broken at entry: ${result2.brokenAt}`);
  console.log(`  Reason: ${result2.reason}`);
  console.log(`  Entries checked before break: ${result2.checked}`);
}
