import { describe, it, expect } from "vitest";
import { claimCost } from "../src/pricing.js";

describe("claimCost", () => {
  const tiers = [600_000_000, 425_000_000, 300_000_000, 150_000_000, 75_000_000, 50_000_000];

  it("returns null for empty tiers", () => {
    expect(claimCost([], 3)).toBeNull();
  });

  it("returns tier by name length index", () => {
    expect(claimCost(tiers, 1)).toBe(600_000_000);
    expect(claimCost(tiers, 3)).toBe(300_000_000);
    expect(claimCost(tiers, 6)).toBe(50_000_000);
  });

  it("clamps long names to last tier", () => {
    expect(claimCost(tiers, 7)).toBe(50_000_000);
    expect(claimCost(tiers, 62)).toBe(50_000_000);
  });

  it("single-tier array returns that tier for all lengths", () => {
    expect(claimCost([25_000_000], 1)).toBe(25_000_000);
    expect(claimCost([25_000_000], 10)).toBe(25_000_000);
  });

  it("treats nameLength 0 as 1", () => {
    expect(claimCost(tiers, 0)).toBe(600_000_000);
  });
});
