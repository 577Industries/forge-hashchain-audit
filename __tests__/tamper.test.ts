import { describe, it, expect } from "vitest";
import { AuditLedger } from "../src/ledger.js";
import { InMemoryStorage } from "../src/storage/memory.js";

describe("tamper detection", () => {
  it("detects when entry data is modified", async () => {
    const storage = new InMemoryStorage();
    const ledger = new AuditLedger({ storage });

    await ledger.append("create", "alice");
    await ledger.append("update", "bob");
    await ledger.append("delete", "charlie");

    // Tamper: modify the second entry's action type
    const entries = storage._getEntries();
    entries[1] = { ...entries[1], actionType: "TAMPERED" };

    const result = await ledger.verify();
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("hash_mismatch");
    expect(result.brokenAt).toBe(entries[1].id);
  });

  it("detects when entry hash is directly modified", async () => {
    const storage = new InMemoryStorage();
    const ledger = new AuditLedger({ storage });

    await ledger.append("create", "alice");
    await ledger.append("update", "bob");

    // Tamper: modify the first entry's hash
    const entries = storage._getEntries();
    entries[0] = { ...entries[0], entryHash: "0".repeat(64) };

    const result = await ledger.verify();
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("hash_mismatch");
  });

  it("detects tampering via Merkle anchor verification", async () => {
    const storage = new InMemoryStorage();
    const ledger = new AuditLedger({ storage });

    await ledger.append("a", "actor");
    await ledger.append("b", "actor");
    await ledger.append("c", "actor");

    const anchor = await ledger.createAnchor();
    expect((await ledger.verifyAnchor(anchor)).valid).toBe(true);

    // Tamper: modify an entry's hash
    const entries = storage._getEntries();
    entries[1] = { ...entries[1], entryHash: "tampered" };

    const result = await ledger.verifyAnchor(anchor);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("merkle_root_mismatch");
  });

  it("detects insertion of extra entries via anchor", async () => {
    const storage = new InMemoryStorage();
    const ledger = new AuditLedger({ storage });

    await ledger.append("a", "actor");
    await ledger.append("b", "actor");

    const anchor = await ledger.createAnchor();

    // Tamper: insert an entry between existing ones
    const entries = storage._getEntries();
    const fake = {
      ...entries[0],
      id: "fake-id",
      entryHash: "fake-hash",
    };
    entries.splice(1, 0, fake);

    const result = await ledger.verifyAnchor(anchor);
    expect(result.valid).toBe(false);
  });
});
