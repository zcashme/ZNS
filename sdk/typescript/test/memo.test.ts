import { describe, it, expect } from "vitest";
import {
  listPayload,
  delistPayload,
  updatePayload,
  buildClaimMemo,
  buildBuyMemo,
  buildListMemo,
  buildDelistMemo,
  buildUpdateMemo,
} from "../src/memo.js";

describe("signing payloads", () => {
  it("listPayload", () => {
    expect(listPayload("alice", 100000, 1)).toBe("LIST:alice:100000:1");
  });

  it("delistPayload", () => {
    expect(delistPayload("alice", 2)).toBe("DELIST:alice:2");
  });

  it("updatePayload", () => {
    expect(updatePayload("alice", "u1newaddr", 3)).toBe("UPDATE:alice:u1newaddr:3");
  });
});

describe("memo builders", () => {
  it("buildClaimMemo", () => {
    expect(buildClaimMemo("alice", "u1myaddr")).toBe("ZNS:CLAIM:alice:u1myaddr");
  });

  it("buildBuyMemo", () => {
    expect(buildBuyMemo("alice", "u1buyer")).toBe("ZNS:BUY:alice:u1buyer");
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

  it("throws on invalid name", () => {
    expect(() => buildClaimMemo("INVALID", "u1addr")).toThrow("Invalid name");
    expect(() => buildBuyMemo("--bad", "u1addr")).toThrow("Invalid name");
  });
});
