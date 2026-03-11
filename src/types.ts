/**
 * Type definitions for hashchain-audit.
 */

export interface AuditEntry {
  id: string;
  actionType: string;
  actor: string;
  entityType: string | null;
  entityId: string | null;
  details: Record<string, unknown> | null;
  prevHash: string | null;
  entryHash: string;
  signature: string | null;
  createdAt: string;
}

export interface AppendOptions {
  entityType?: string;
  entityId?: string;
  details?: Record<string, unknown>;
}

export interface MerkleAnchor {
  id: string;
  merkleRoot: string;
  signature: string | null;
  firstEntryId: string;
  lastEntryId: string;
  entryCount: number;
  createdAt: string;
}

export interface VerificationResult {
  valid: boolean;
  brokenAt: string | null;
  checked: number;
  reason?: "hash_mismatch" | "invalid_signature";
}

export interface LedgerConfig {
  storage?: StorageAdapter;
  privateKey?: string;
  anchorInterval?: number;
}

export interface StorageAdapter {
  getLastEntry(): Promise<AuditEntry | null>;
  append(entry: AuditEntry): Promise<void>;
  getEntries(options?: { limit?: number; offset?: number }): Promise<AuditEntry[]>;
  getEntriesSince(entryId: string): Promise<AuditEntry[]>;
}
