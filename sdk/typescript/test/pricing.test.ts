import { describe, it, expect } from "vitest";
import { claimCost } from "../src/pricing.js";

describe("claimCost", () => {
  it("returns 6 ZEC for 1-char names", () => {
    expect(claimCost(1)).toBe(600_000_000);
  });

  it("returns 4.25 ZEC for 2-char names", () => {
    expect(claimCost(2)).toBe(425_000_000);
  });

  it("returns 3 ZEC for 3-char names", () => {
    expect(claimCost(3)).toBe(300_000_000);
  });

  it("returns 1.5 ZEC for 4-char names", () => {
    expect(claimCost(4)).toBe(150_000_000);
  });

  it("returns 0.75 ZEC for 5-char names", () => {
    expect(claimCost(5)).toBe(75_000_000);
  });

  it("returns 0.50 ZEC for 6-char names", () => {
    expect(claimCost(6)).toBe(50_000_000);
  });

  it("returns 0.25 ZEC for 7+ char names", () => {
    expect(claimCost(7)).toBe(25_000_000);
    expect(claimCost(10)).toBe(25_000_000);
    expect(claimCost(62)).toBe(25_000_000);
  });
});
