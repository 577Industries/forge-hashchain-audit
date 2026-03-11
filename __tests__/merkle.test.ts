import { describe, it, expect } from "vitest";
import { computeMerkleRoot } from "../src/merkle.js";

describe("computeMerkleRoot", () => {
  it("returns empty string for empty list", () => {
    expect(computeMerkleRoot([])).toBe("");
  });

  it("returns the hash itself for a single element", () => {
    const hash = "abc123def456";
    expect(computeMerkleRoot([hash])).toBe(hash);
  });

  it("computes root for 2 hashes", () => {
    const root = computeMerkleRoot(["hash1", "hash2"]);
    expect(root).toMatch(/^[a-f0-9]{64}$/);
  });

  it("handles odd number of hashes (duplicates last)", () => {
    const root3 = computeMerkleRoot(["a", "b", "c"]);
    expect(root3).toMatch(/^[a-f0-9]{64}$/);
    // Verify it's different from even count
    const root2 = computeMerkleRoot(["a", "b"]);
    expect(root3).not.toBe(root2);
  });

  it("computes root for power-of-2 count", () => {
    const hashes = ["h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8"];
    const root = computeMerkleRoot(hashes);
    expect(root).toMatch(/^[a-f0-9]{64}$/);
  });

  it("produces deterministic results", () => {
    const hashes = ["foo", "bar", "baz"];
    const root1 = computeMerkleRoot(hashes);
    const root2 = computeMerkleRoot(hashes);
    expect(root1).toBe(root2);
  });

  it("is sensitive to order", () => {
    const root1 = computeMerkleRoot(["a", "b"]);
    const root2 = computeMerkleRoot(["b", "a"]);
    expect(root1).not.toBe(root2);
  });
});
