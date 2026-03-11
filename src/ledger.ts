/**
 * AuditLedger — the main API for hashchain-audit.
 * Wraps hash chaining, signing, and Merkle anchoring.
 */

import crypto from "node:crypto";
import type {
  AuditEntry,
  AppendOptions,
  MerkleAnchor,
  VerificationResult,
  LedgerConfig,
  StorageAdapter,
} from "./types.js";
import { computeHash, signHash, verifySignature, loadPrivateKey, derivePublicKey } from "./crypto.js";
import { computeMerkleRoot } from "./merkle.js";
import { InMemoryStorage } from "./storage/memory.js";

export class AuditLedger {
  private storage: StorageAdapter;
  private privateKey: crypto.KeyObject | null = null;
  private publicKey: crypto.KeyObject | null = null;
  private anchorInterval: number;
  private appendCount = 0;
  private anchors: MerkleAnchor[] = [];

  constructor(config?: LedgerConfig) {
    this.storage = config?.storage ?? new InMemoryStorage();
    this.anchorInterval = config?.anchorInterval ?? 100;

    if (config?.privateKey) {
      this.privateKey = loadPrivateKey(config.privateKey);
      this.publicKey = derivePublicKey(this.privateKey);
    }
  }

  /**
   * Append a new entry to the audit trail.
   */
  async append(
    actionType: string,
    actor: string,
    options?: AppendOptions
  ): Promise<AuditEntry> {
    const lastEntry = await this.storage.getLastEntry();
    const prevHash = lastEntry?.entryHash ?? null;
    const timestamp = new Date().toISOString();
    const detailsJson = options?.details
      ? JSON.stringify(options.details)
      : "{}";

    const entryHash = computeHash(
      prevHash,
      actionType,
      actor,
      options?.entityType ?? null,
      options?.entityId ?? null,
      timestamp,
      detailsJson
    );

    const signature = this.privateKey
      ? signHash(entryHash, this.privateKey)
      : null;

    const entry: AuditEntry = {
      id: crypto.randomUUID(),
      actionType,
      actor,
      entityType: options?.entityType ?? null,
      entityId: options?.entityId ?? null,
      details: options?.details ?? null,
      prevHash,
      entryHash,
      signature,
      createdAt: timestamp,
    };

    await this.storage.append(entry);
    this.appendCount++;

    return entry;
  }

  /**
   * Verify the integrity of the entire hash chain.
   */
  async verify(): Promise<VerificationResult> {
    const entries = await this.storage.getEntries();
    let prevHash: string | null = null;
    let checked = 0;

    for (const entry of entries) {
      const expectedHash = computeHash(
        prevHash,
        entry.actionType,
        entry.actor,
        entry.entityType,
        entry.entityId,
        entry.createdAt,
        JSON.stringify(entry.details ?? {})
      );

      if (entry.entryHash !== expectedHash) {
        return {
          valid: false,
          brokenAt: entry.id,
          checked,
          reason: "hash_mismatch",
        };
      }

      if (entry.signature && this.publicKey) {
        if (!verifySignature(entry.entryHash, entry.signature, this.publicKey)) {
          return {
            valid: false,
            brokenAt: entry.id,
            checked,
            reason: "invalid_signature",
          };
        }
      }

      prevHash = entry.entryHash;
      checked++;
    }

    return { valid: true, brokenAt: null, checked };
  }

  /**
   * Create a Merkle anchor over all entries since the last anchor.
   */
  async createAnchor(): Promise<MerkleAnchor> {
    const entries = await this.storage.getEntries();
    const lastAnchor =
      this.anchors.length > 0
        ? this.anchors[this.anchors.length - 1]
        : null;

    let anchorEntries: AuditEntry[];
    if (lastAnchor) {
      const lastIdx = entries.findIndex((e) => e.id === lastAnchor.lastEntryId);
      anchorEntries = lastIdx >= 0 ? entries.slice(lastIdx + 1) : entries;
    } else {
      anchorEntries = entries;
    }

    if (anchorEntries.length === 0) {
      throw new Error("No entries to anchor");
    }

    const hashes = anchorEntries.map((e) => e.entryHash);
    const merkleRoot = computeMerkleRoot(hashes);
    const signature = this.privateKey
      ? signHash(merkleRoot, this.privateKey)
      : null;

    const anchor: MerkleAnchor = {
      id: crypto.randomUUID(),
      merkleRoot,
      signature,
      firstEntryId: anchorEntries[0].id,
      lastEntryId: anchorEntries[anchorEntries.length - 1].id,
      entryCount: anchorEntries.length,
      createdAt: new Date().toISOString(),
    };

    this.anchors.push(anchor);
    this.appendCount = 0;
    return anchor;
  }

  /**
   * Verify a Merkle anchor by recomputing the root.
   */
  async verifyAnchor(
    anchor: MerkleAnchor
  ): Promise<{ valid: boolean; reason?: string }> {
    const entries = await this.storage.getEntries();
    const firstIdx = entries.findIndex((e) => e.id === anchor.firstEntryId);
    const lastIdx = entries.findIndex((e) => e.id === anchor.lastEntryId);

    if (firstIdx === -1 || lastIdx === -1) {
      return { valid: false, reason: "anchor_entries_not_found" };
    }

    const anchorEntries = entries.slice(firstIdx, lastIdx + 1);

    if (anchorEntries.length !== anchor.entryCount) {
      return { valid: false, reason: "entry_count_mismatch" };
    }

    const hashes = anchorEntries.map((e) => e.entryHash);
    const recomputedRoot = computeMerkleRoot(hashes);

    if (recomputedRoot !== anchor.merkleRoot) {
      return { valid: false, reason: "merkle_root_mismatch" };
    }

    if (anchor.signature && this.publicKey) {
      if (!verifySignature(anchor.merkleRoot, anchor.signature, this.publicKey)) {
        return { valid: false, reason: "invalid_signature" };
      }
    }

    return { valid: true };
  }

  /**
   * Get entries from the audit trail.
   */
  async getEntries(options?: {
    limit?: number;
    offset?: number;
  }): Promise<AuditEntry[]> {
    return this.storage.getEntries(options);
  }

  /**
   * Get all Merkle anchors.
   */
  getAnchors(): MerkleAnchor[] {
    return [...this.anchors];
  }
}
