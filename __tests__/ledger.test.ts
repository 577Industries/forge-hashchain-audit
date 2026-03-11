import { describe, it, expect } from "vitest";
import { AuditLedger } from "../src/ledger.js";

describe("AuditLedger", () => {
  it("appends a single entry", async () => {
    const ledger = new AuditLedger();
    const entry = await ledger.append("user.login", "alice@example.com");

    expect(entry.actionType).toBe("user.login");
    expect(entry.actor).toBe("alice@example.com");
    expect(entry.entryHash).toMatch(/^[a-f0-9]{64}$/);
    expect(entry.prevHash).toBeNull();
  });

  it("chains entries with prevHash", async () => {
    const ledger = new AuditLedger();
    const first = await ledger.append("action.a", "actor1");
    const second = await ledger.append("action.b", "actor2");

    expect(second.prevHash).toBe(first.entryHash);
  });

  it("verifies a valid chain", async () => {
    const ledger = new AuditLedger();
    await ledger.append("create", "alice");
    await ledger.append("update", "bob");
    await ledger.append("delete", "charlie");

    const result = await ledger.verify();
    expect(result.valid).toBe(true);
    expect(result.checked).toBe(3);
    expect(result.brokenAt).toBeNull();
  });

  it("retrieves entries with limit and offset", async () => {
    const ledger = new AuditLedger();
    await ledger.append("a", "actor");
    await ledger.append("b", "actor");
    await ledger.append("c", "actor");

    const page = await ledger.getEntries({ limit: 2, offset: 1 });
    expect(page).toHaveLength(2);
    expect(page[0].actionType).toBe("b");
    expect(page[1].actionType).toBe("c");
  });

  it("stores entity type, entity ID, and details", async () => {
    const ledger = new AuditLedger();
    const entry = await ledger.append("record.update", "admin", {
      entityType: "invoice",
      entityId: "inv-123",
      details: { amount: 5000, currency: "USD" },
    });

    expect(entry.entityType).toBe("invoice");
    expect(entry.entityId).toBe("inv-123");
    expect(entry.details).toEqual({ amount: 5000, currency: "USD" });
  });
});
