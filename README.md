# @577-industries/hashchain-audit

[![npm version](https://img.shields.io/npm/v/@577-industries/hashchain-audit)](https://www.npmjs.com/package/@577-industries/hashchain-audit)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)

A tamper-evident audit trail using three cryptographic layers: SHA-256 hash chaining, Ed25519 digital signatures, and Merkle tree anchoring. Zero runtime dependencies — uses Node.js built-in `crypto`.

Implements the core algorithm described in the **"Hash-Chained Audit Ledger"** patent (March 2026) by 577 Industries.

## How It Works

```
  Entry N-1          Entry N            Verification
  ─────────         ─────────          ─────────────
  hash(N-1) ──────► prevHash           Recompute each
                    action    ──┐       hash from its
                    actor       ├─► SHA-256 ──► entryHash
                    timestamp   │               │
                    details   ──┘           Ed25519 ──► signature
                                                │
                              Merkle Root ◄─────┘ (periodic anchor)
```

## Quick Start

```bash
npm install @577-industries/hashchain-audit
```

```typescript
import { AuditLedger, generateKeyPair } from "@577-industries/hashchain-audit";

// Generate signing keys (or provide your own PEM)
const keys = generateKeyPair();
const ledger = new AuditLedger({ privateKey: keys.privateKey });

// Append entries — each is hash-chained to the previous
await ledger.append("user.login", "alice@example.com");
await ledger.append("record.update", "alice@example.com", {
  entityType: "invoice",
  entityId: "inv-123",
  details: { amount: 5000 },
});

// Verify chain integrity
const result = await ledger.verify();
console.log(result.valid);   // true
console.log(result.checked); // 2

// Create a Merkle anchor for range verification
const anchor = await ledger.createAnchor();
const anchorResult = await ledger.verifyAnchor(anchor);
console.log(anchorResult.valid); // true
```

## API Reference

### `AuditLedger`

| Method | Description |
|--------|-------------|
| `new AuditLedger(config?)` | Create a ledger with optional signing key and storage adapter |
| `append(action, actor, options?)` | Append a hash-chained (and optionally signed) entry |
| `verify()` | Verify the entire chain's integrity |
| `createAnchor()` | Create a Merkle tree anchor over recent entries |
| `verifyAnchor(anchor)` | Verify a Merkle anchor by recomputing the root |
| `getEntries(options?)` | Retrieve entries with optional limit/offset |

### Crypto Utilities

| Function | Description |
|----------|-------------|
| `generateKeyPair()` | Generate Ed25519 key pair (PEM-encoded) |
| `computeHash(...)` | SHA-256 pipe-delimited hash |
| `signHash(hash, key)` | Ed25519 signature |
| `verifySignature(hash, sig, key)` | Verify Ed25519 signature |

### Pluggable Storage

Implement `StorageAdapter` for custom persistence:

```typescript
interface StorageAdapter {
  getLastEntry(): Promise<AuditEntry | null>;
  append(entry: AuditEntry): Promise<void>;
  getEntries(options?): Promise<AuditEntry[]>;
  getEntriesSince(entryId: string): Promise<AuditEntry[]>;
}
```

Built-in: `InMemoryStorage` (default).

## Architecture

Three cryptographic layers:

1. **Hash Chain** — Each entry's hash includes the previous entry's hash, creating a tamper-evident chain
2. **Digital Signatures** — Ed25519 signatures on each hash prove authenticity
3. **Merkle Anchors** — Periodic Merkle tree roots enable efficient range verification

Based on the ["Hash-Chained Audit Ledger" patent](https://www.577industries.com/forge) by 577 Industries.

---

Extracted from [FORGE OS](https://www.577industries.com) by **577 Industries**.
