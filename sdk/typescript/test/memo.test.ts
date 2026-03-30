import { describe, it, expect } from "vitest";
import {
  claimPayload,
  buyPayload,
  listPayload,
  delistPayload,
  updatePayload,
  setPricePayload,
  buildClaimMemo,
  buildBuyMemo,
  buildListMemo,
  buildDelistMemo,
  buildUpdateMemo,
  buildSetPriceMemo,
} from "../src/memo.js";

describe("signing payloads", () => {
  it("claimPayload", () => {
    expect(claimPayload("alice", "u1myaddr")).toBe("CLAIM:alice:u1myaddr");
  });

  it("buyPayload", () => {
    expect(buyPayload("alice", "u1buyer")).toBe("BUY:alice:u1buyer");
  });

  it("listPayload", () => {
    expect(listPayload("alice", 100000, 1)).toBe("LIST:alice:100000:1");
  });

  it("delistPayload", () => {
    expect(delistPayload("alice", 2)).toBe("DELIST:alice:2");
  });

  it("updatePayload", () => {
    expect(updatePayload("alice", "u1newaddr", 3)).toBe("UPDATE:alice:u1newaddr:3");
  });

  it("setPricePayload", () => {
    expect(setPricePayload([60000, 42500, 2500], 1)).toBe("SETPRICE:3:60000:42500:2500:1");
  });
});

describe("memo builders", () => {
  it("buildClaimMemo", () => {
    expect(buildClaimMemo("alice", "u1myaddr", "sig123")).toBe(
      "ZNS:CLAIM:alice:u1myaddr:sig123",
    );
  });

  it("buildBuyMemo", () => {
    expect(buildBuyMemo("alice", "u1buyer", "sig456")).toBe(
      "ZNS:BUY:alice:u1buyer:sig456",
    );
  });

  it("buildListMemo", () => {
    expect(buildListMemo("alice", 100000, 1, "sig123")).toBe(
      "ZNS:LIST:alice:100000:1:sig123",
    );
  });

  it("buildDelistMemo", () => {
    expect(buildDelistMemo("alice", 2, "sig456")).toBe("ZNS:DELIST:alice:2:sig456");
  });

  it("buildUpdateMemo", () => {
    expect(buildUpdateMemo("alice", "u1new", 3, "sig789")).toBe(
      "ZNS:UPDATE:alice:u1new:3:sig789",
    );
  });

  it("buildSetPriceMemo", () => {
    expect(buildSetPriceMemo([60000, 42500, 2500], 1, "sigABC")).toBe(
      "ZNS:SETPRICE:3:60000:42500:2500:1:sigABC",
    );
  });

  it("throws on invalid name", () => {
    expect(() => buildClaimMemo("INVALID", "u1addr", "sig")).toThrow("Invalid name");
    expect(() => buildBuyMemo("--bad", "u1addr", "sig")).toThrow("Invalid name");
  });
});
