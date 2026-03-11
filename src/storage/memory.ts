/**
 * In-memory storage adapter for hashchain-audit.
 * Suitable for testing and demonstrations.
 */

import type { AuditEntry, StorageAdapter } from "../types.js";

export class InMemoryStorage implements StorageAdapter {
  private entries: AuditEntry[] = [];

  async getLastEntry(): Promise<AuditEntry | null> {
    return this.entries.length > 0
      ? this.entries[this.entries.length - 1]
      : null;
  }

  async append(entry: AuditEntry): Promise<void> {
    this.entries.push(entry);
  }

  async getEntries(options?: {
    limit?: number;
    offset?: number;
  }): Promise<AuditEntry[]> {
    const offset = options?.offset ?? 0;
    const limit = options?.limit ?? this.entries.length;
    return this.entries.slice(offset, offset + limit);
  }

  async getEntriesSince(entryId: string): Promise<AuditEntry[]> {
    const index = this.entries.findIndex((e) => e.id === entryId);
    if (index === -1) return [];
    return this.entries.slice(index + 1);
  }

  /** Directly access entries for testing (e.g., tampering simulation). */
  _getEntries(): AuditEntry[] {
    return this.entries;
  }
}
