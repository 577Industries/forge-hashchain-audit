import { describe, it, expect } from "vitest";
import {
  generateKeyPair,
  signHash,
  verifySignature,
  loadPrivateKey,
  loadPublicKey,
  derivePublicKey,
} from "../src/crypto.js";
import { AuditLedger } from "../src/ledger.js";

describe("Ed25519 signing", () => {
  it("generates a valid key pair", () => {
    const keys = generateKeyPair();
    expect(keys.privateKey).toContain("BEGIN PRIVATE KEY");
    expect(keys.publicKey).toContain("BEGIN PUBLIC KEY");
  });

  it("signs and verifies a hash", () => {
    const keys = generateKeyPair();
    const priv = loadPrivateKey(keys.privateKey);
    const pub = loadPublicKey(keys.publicKey);

    const hash = "a".repeat(64);
    const sig = signHash(hash, priv);
    expect(verifySignature(hash, sig, pub)).toBe(true);
  });

  it("rejects invalid signature", () => {
    const keys = generateKeyPair();
    const pub = loadPublicKey(keys.publicKey);

    const hash = "b".repeat(64);
    expect(verifySignature(hash, "invalidsignature", pub)).toBe(false);
  });

  it("rejects signature from wrong key", () => {
    const keys1 = generateKeyPair();
    const keys2 = generateKeyPair();
    const priv1 = loadPrivateKey(keys1.privateKey);
    const pub2 = loadPublicKey(keys2.publicKey);

    const hash = "c".repeat(64);
    const sig = signHash(hash, priv1);
    expect(verifySignature(hash, sig, pub2)).toBe(false);
  });

  it("derives public key from private key", () => {
    const keys = generateKeyPair();
    const priv = loadPrivateKey(keys.privateKey);
    const derived = derivePublicKey(priv);
    const pub = loadPublicKey(keys.publicKey);

    const hash = "d".repeat(64);
    const sig = signHash(hash, priv);
    expect(verifySignature(hash, sig, derived)).toBe(true);
    expect(verifySignature(hash, sig, pub)).toBe(true);
  });
});

describe("AuditLedger with signing", () => {
  it("signs entries when private key is provided", async () => {
    const keys = generateKeyPair();
    const ledger = new AuditLedger({ privateKey: keys.privateKey });

    const entry = await ledger.append("test", "actor");
    expect(entry.signature).not.toBeNull();
    expect(entry.signature!.length).toBeGreaterThan(0);
  });

  it("verifies signed chain", async () => {
    const keys = generateKeyPair();
    const ledger = new AuditLedger({ privateKey: keys.privateKey });

    await ledger.append("a", "actor");
    await ledger.append("b", "actor");

    const result = await ledger.verify();
    expect(result.valid).toBe(true);
    expect(result.checked).toBe(2);
  });

  it("does not sign when no key provided", async () => {
    const ledger = new AuditLedger();
    const entry = await ledger.append("test", "actor");
    expect(entry.signature).toBeNull();
  });

  it("passes verification with null signatures", async () => {
    const ledger = new AuditLedger();
    await ledger.append("a", "actor");
    await ledger.append("b", "actor");

    const result = await ledger.verify();
    expect(result.valid).toBe(true);
  });
});
