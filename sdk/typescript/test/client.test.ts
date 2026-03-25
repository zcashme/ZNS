import { describe, it, expect, vi, beforeEach } from "vitest";
import { createClient } from "../src/client.js";
import { UFVK } from "../src/constants.js";
import { ErrorType } from "../src/errors.js";

const mockStatus = {
  synced_height: 3902500,
  admin_pubkey: "abc123",
  ufvk: UFVK,
  registered: 42,
  listed: 3,
};

function mockFetch(result: unknown) {
  return vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({ jsonrpc: "2.0", id: 1, result }),
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("createClient", () => {
  it("verifies UFVK on connect", async () => {
    globalThis.fetch = mockFetch(mockStatus);
    const client = await createClient("http://localhost:3000");
    expect(client.verified).toBe(true);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it("throws on UFVK mismatch", async () => {
    globalThis.fetch = mockFetch({ ...mockStatus, ufvk: "wrong" });
    await expect(createClient("http://localhost:3000")).rejects.toMatchObject({
      type: ErrorType.UfvkMismatch,
    });
  });

  it("skips verification with skipVerify", async () => {
    globalThis.fetch = mockFetch(null);
    const client = await createClient("http://localhost:3000", { skipVerify: true });
    expect(client.verified).toBe(false);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});

describe("client methods", () => {
  it("resolve returns result", async () => {
    const reg = { name: "alice", address: "u1addr", txid: "tx1", height: 100, nonce: 0, signature: null, listing: null };
    let callCount = 0;
    globalThis.fetch = vi.fn().mockImplementation(() => {
      callCount++;
      const result = callCount === 1 ? mockStatus : reg;
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ jsonrpc: "2.0", id: callCount, result }),
      });
    });

    const client = await createClient("http://localhost:3000");
    const result = await client.resolve("alice");
    expect(result?.name).toBe("alice");
  });

  it("resolve returns null for unknown name", async () => {
    let callCount = 0;
    globalThis.fetch = vi.fn().mockImplementation(() => {
      callCount++;
      const result = callCount === 1 ? mockStatus : null;
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ jsonrpc: "2.0", id: callCount, result }),
      });
    });

    const client = await createClient("http://localhost:3000");
    const result = await client.resolve("doesnotexist");
    expect(result).toBeNull();
  });
});
