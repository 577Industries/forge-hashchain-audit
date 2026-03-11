/**
 * Merkle tree implementation for periodic anchoring.
 * Binary Merkle tree with odd-leaf duplication.
 */

import crypto from "node:crypto";

/**
 * Compute a binary Merkle root from a list of hashes.
 * Uses SHA-256 for internal nodes. Odd-count leaves are duplicated.
 */
export function computeMerkleRoot(hashes: string[]): string {
  if (hashes.length === 0) return "";
  if (hashes.length === 1) return hashes[0];

  let layer = [...hashes];

  while (layer.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = layer[i + 1] ?? left; // duplicate if odd
      const combined = crypto
        .createHash("sha256")
        .update(left + right)
        .digest("hex");
      next.push(combined);
    }
    layer = next;
  }

  return layer[0];
}
