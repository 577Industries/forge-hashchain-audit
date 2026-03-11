/**
 * Cryptographic primitives for hashchain-audit.
 * SHA-256 hashing, Ed25519 signing, and key management.
 */

import crypto from "node:crypto";

/**
 * Compute a SHA-256 hash using pipe-delimited concatenation.
 * Format: prevHash|actionType|actor|entityType|entityId|timestamp|details
 */
export function computeHash(
  prevHash: string | null,
  actionType: string,
  actor: string,
  entityType: string | null,
  entityId: string | null,
  timestamp: string,
  details: string
): string {
  const payload = [
    prevHash ?? "GENESIS",
    actionType,
    actor,
    entityType ?? "",
    entityId ?? "",
    timestamp,
    details,
  ].join("|");

  return crypto.createHash("sha256").update(payload).digest("hex");
}

/**
 * Sign a hash using an Ed25519 private key.
 */
export function signHash(
  entryHash: string,
  privateKey: crypto.KeyObject
): string {
  return crypto
    .sign(null, Buffer.from(entryHash), privateKey)
    .toString("base64");
}

/**
 * Verify a signature against a hash using an Ed25519 public key.
 */
export function verifySignature(
  entryHash: string,
  signature: string,
  publicKey: crypto.KeyObject
): boolean {
  return crypto.verify(
    null,
    Buffer.from(entryHash),
    publicKey,
    Buffer.from(signature, "base64")
  );
}

/**
 * Generate an Ed25519 key pair. Returns PEM-encoded strings.
 */
export function generateKeyPair(): { privateKey: string; publicKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    publicKey: publicKey.export({ type: "spki", format: "pem" }) as string,
  };
}

/**
 * Load a PEM-encoded private key.
 */
export function loadPrivateKey(pem: string): crypto.KeyObject {
  return crypto.createPrivateKey(pem.replace(/\\n/g, "\n"));
}

/**
 * Load a PEM-encoded public key.
 */
export function loadPublicKey(pem: string): crypto.KeyObject {
  return crypto.createPublicKey(pem.replace(/\\n/g, "\n"));
}

/**
 * Derive the public key from a private key.
 */
export function derivePublicKey(privateKey: crypto.KeyObject): crypto.KeyObject {
  return crypto.createPublicKey(privateKey);
}
