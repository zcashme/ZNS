import { describe, it, expect, vi, beforeEach } from "vitest";
import { ZNS, DEFAULT_URL, TESTNET_UIVK, BUY_COMMISSION } from "../src/zns.js";

// Valid testnet unified address (bech32m format)
const VALID_TESTNET_ADDR = "utest100qlkeru5c3m5kfrwe2hsmcfzmusreaza2prdyelg2kd2tr2842nceq952vay3gpmgky09fgft4z57h4z2zqzz5rcwgd4q90u54ek5yyca4s6e6y2jja9sww27kzedzznjcupcu0svq2exvq995c0lhl5zm53g4ksnm2xuwt3snv4dgh";

// CamelCase mock status (what SDK now returns)
const mockStatus = {
  syncedHeight: 3902500,
  adminPubkey: "YCsjrC6I8UFsWwGJIpCQx9FI98Q4g3E7+8CQ3E8M9OE=",
  uivk: TESTNET_UIVK,
  address: VALID_TESTNET_ADDR,
  registered: 42,
  listed: 3,
  pricing: {
    nonce: 1,
    height: 3900000,
    tiers: [600_000_000, 425_000_000, 300_000_000, 150_000_000, 75_000_000, 50_000_000],
  },
};

// Snake_case mock (what RPC actually returns - used for mocking)
const mockRpcStatus = {
  synced_height: 3902500,
  admin_pubkey: "YCsjrC6I8UFsWwGJIpCQx9FI98Q4g3E7+8CQ3E8M9OE=",
  uivk: TESTNET_UIVK,
  address: VALID_TESTNET_ADDR,
  registered: 42,
  listed: 3,
  pricing: {
    nonce: 1,
    height: 3900000,
    tiers: [600_000_000, 425_000_000, 300_000_000, 150_000_000, 75_000_000, 50_000_000],
  },
};

function mockRpc(result: unknown) {
  return vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({ jsonrpc: "2.0", id: 1, result }),
  });
}

function mockRpcSequence(results: unknown[]) {
  let i = 0;
  return vi.fn().mockImplementation(() => {
    const result = results[i] ?? null;
    i++;
    return Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ jsonrpc: "2.0", id: i, result }),
    });
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("ZNS constructor", () => {
  it("creates instance synchronously without network calls", () => {
    const zns = new ZNS();
    expect(zns).toBeInstanceOf(ZNS);
    expect(zns.verified).toBe(false);
  });

  it("uses custom url", () => {
    const zns = new ZNS({ url: "http://localhost:3000" });
    expect(zns).toBeInstanceOf(ZNS);
  });
});

describe("ZNS.verify", () => {
  it("verifies server UIVK", async () => {
    globalThis.fetch = mockRpc(mockRpcStatus);
    const zns = new ZNS();
    await zns.verify();
    expect(zns.verified).toBe(true);
  });

  it("throws on UIVK mismatch", async () => {
    globalThis.fetch = mockRpc({ ...mockRpcStatus, uivk: "wrong" });
    const zns = new ZNS();
    await expect(zns.verify()).rejects.toThrow("UIVK mismatch");
    expect(zns.verified).toBe(false);
  });
});

describe("ZNS.status", () => {
  it("fetches server status with camelCase fields", async () => {
    globalThis.fetch = mockRpc(mockRpcStatus);
    const zns = new ZNS();
    const status = await zns.status();

    // Now returns camelCase
    expect(status.adminPubkey).toBe(mockRpcStatus.admin_pubkey);
    expect(status.syncedHeight).toBe(3902500);
    expect(status.address).toBe(VALID_TESTNET_ADDR);
    expect(status.pricing?.tiers).toEqual(mockRpcStatus.pricing.tiers);
  });
});

describe("resolveName", () => {
  it("returns registration with listing", async () => {
    const reg = {
      name: "alice",
      address: "utest1addr",
      txid: "tx1",
      height: 100,
      nonce: 0,
      signature: null,
      last_action: "CLAIM",
      pubkey: null,
      listing: { name: "alice", price: 100_000, pay_taddr: "t1testaddr", nonce: 1, txid: "tx2", height: 200, signature: "sig1", pubkey: null, pending_buy: null },
    };
    globalThis.fetch = mockRpc(reg);

    const zns = new ZNS();
    const result = await zns.resolveName("alice");

    expect(result).not.toBeNull();
    if (result) {
      expect(result.name).toBe("alice");
      expect(result.address).toBe("utest1addr");
      expect(result.lastAction).toBe("CLAIM"); // camelCase
      expect(result.listing).not.toBeNull();
      expect(result.listing?.payTaddr).toBe("t1testaddr"); // camelCase
    }
  });

  it("returns sovereign registration", async () => {
    const reg = {
      name: "alice",
      address: "utest1addr",
      txid: "tx1",
      height: 100,
      nonce: 0,
      signature: "sig1",
      last_action: "CLAIM",
      pubkey: "differentpubkeybase64=",
      listing: null,
    };
    globalThis.fetch = mockRpc(reg);

    const zns = new ZNS();
    const result = await zns.resolveName("alice");

    if (result) {
      expect(result.pubkey).toBe("differentpubkeybase64=");
      expect(result.listing).toBeNull();
    }
  });

  it("returns null for unknown name", async () => {
    globalThis.fetch = mockRpc(null);
    const zns = new ZNS();
    const result = await zns.resolveName("doesnotexist");
    expect(result).toBeNull();
  });
});

describe("resolveAddress", () => {
  it("returns registrations for address", async () => {
    const regs = [
      { name: "alice", address: "utest1addr", txid: "tx1", height: 100, nonce: 0, signature: null, last_action: "CLAIM", pubkey: null, listing: null },
    ];
    globalThis.fetch = mockRpc(regs);

    const zns = new ZNS();
    const result = await zns.resolveAddress("utest1addr");

    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("alice");
  });

  it("returns empty array for unknown address", async () => {
    globalThis.fetch = mockRpc([]);
    const zns = new ZNS();
    const result = await zns.resolveAddress("unknown");
    expect(result).toEqual([]);
  });
});

describe("isAvailable", () => {
  it("returns true for unregistered name", async () => {
    globalThis.fetch = mockRpc(null);
    const zns = new ZNS();
    expect(await zns.isAvailable("doesnotexist")).toBe(true);
  });

  it("returns false for registered name", async () => {
    const reg = {
      name: "alice", address: "u1", txid: "tx1", height: 100,
      nonce: 0, signature: null, last_action: "CLAIM", pubkey: null, listing: null,
    };
    globalThis.fetch = mockRpc(reg);
    const zns = new ZNS();
    expect(await zns.isAvailable("alice")).toBe(false);
  });

  it("returns false for invalid name without network call", async () => {
    const fetchMock = vi.fn();
    globalThis.fetch = fetchMock;
    const zns = new ZNS();
    expect(await zns.isAvailable("INVALID")).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("listings", () => {
  it("returns listings with camelCase fields", async () => {
    const listings = {
      listings: [
        { name: "bob", price: 100_000, pay_taddr: "t1testaddr", nonce: 1, txid: "tx1", height: 200, signature: "sig1", pubkey: null, pending_buy: null },
      ],
      total: 1,
    };
    globalThis.fetch = mockRpc(listings);
    const zns = new ZNS();
    const result = await zns.listings();

    expect(result.listings).toHaveLength(1);
    expect(result.listings[0].name).toBe("bob");
    expect(result.listings[0].payTaddr).toBe("t1testaddr"); // camelCase
    expect(result.listings[0].pendingBuy).toBeUndefined(); // camelCase
    expect(result.total).toBe(1);
  });

  it("returns pendingBuy with camelCase fields", async () => {
    const listings = {
      listings: [
        { name: "bob", price: 100_000, pay_taddr: "t1testaddr", nonce: 1, txid: "tx1", height: 200, signature: "sig1", pubkey: null, pending_buy: { buyer_ua: "u1buyer", price: 50_000, claim_height: 200, expires_at: 300, txid: "tx3" } },
      ],
      total: 1,
    };
    globalThis.fetch = mockRpc(listings);
    const zns = new ZNS();
    const result = await zns.listings();

    expect(result.listings[0].pendingBuy).toBeDefined();
    expect(result.listings[0].pendingBuy?.buyer).toBe("u1buyer"); // camelCase
    expect(result.listings[0].pendingBuy?.claimHeight).toBe(200); // camelCase
    expect(result.listings[0].pendingBuy?.expiresAt).toBe(300); // camelCase
  });
});

describe("events", () => {
  it("returns events with camelCase fields", async () => {
    const events = {
      events: [
        { id: 1, name: "alice", action: "CLAIM", txid: "tx1", height: 100, ua: "u1addr", price: null, nonce: null, signature: null, pubkey: null },
      ],
      total: 1,
    };
    globalThis.fetch = mockRpc(events);
    const zns = new ZNS();
    const result = await zns.events();

    expect(result.events).toHaveLength(1);
    expect(result.total).toBe(1);
  });
});

describe("verification", () => {
  it("verifyListing returns true with valid admin pubkey", async () => {
    globalThis.fetch = mockRpc(mockRpcStatus);
    const zns = new ZNS();
    const status = await zns.status();

    const listing = { name: "bob", price: 100_000, payTaddr: "t1testaddr", nonce: 1, txid: "tx1", height: 200, signature: "sig1", pubkey: null, pendingBuy: undefined };
    const result = await zns.verifyListing(listing, status.adminPubkey);
    expect(typeof result).toBe("boolean");
  });

  it("verifyRegistration returns false when no signature", async () => {
    globalThis.fetch = mockRpc(mockRpcStatus);
    const zns = new ZNS();
    const status = await zns.status();

    const reg = { name: "alice", address: "u1", txid: "tx1", height: 100, nonce: 0, signature: null, lastAction: "CLAIM", pubkey: null, listing: null };
    const result = await zns.verifyRegistration(reg, status.adminPubkey);
    expect(result).toBe(false);
  });
});

describe("action flows", () => {
  let zns: ZNS;
  let mockPricing: typeof mockStatus.pricing;
  beforeEach(async () => {
    globalThis.fetch = mockRpc(mockRpcStatus);
    zns = new ZNS();
    mockPricing = mockStatus.pricing;
  });

  describe("prepareClaim / complete", () => {
    const validTestnetAddr = VALID_TESTNET_ADDR;

    it("prepareClaim returns payload, cost, and complete method", () => {
      const cost = zns.claimCost(5, mockPricing);
      const result = zns.prepareClaim("alice", validTestnetAddr, cost!);
      expect(result.payload).toBe(`CLAIM:alice:${validTestnetAddr}`);
      expect(result.cost).toBe(75_000_000);
      expect(typeof result.complete).toBe("function");
    });

    it("complete returns memo and uri", () => {
      const cost = zns.claimCost(5, mockPricing);
      const action = zns.prepareClaim("alice", validTestnetAddr, cost!);
      const result = action.complete("sig123", "pubkey456");
      expect(result.memo).toBe(`ZNS:CLAIM:alice:${validTestnetAddr}:sig123:pubkey456`);
      expect(result.uri).toContain("memo=");
    });

    it("complete without userPubkey omits it", () => {
      const cost = zns.claimCost(5, mockPricing);
      const action = zns.prepareClaim("alice", validTestnetAddr, cost!);
      const result = action.complete("sig123");
      expect(result.memo).toBe(`ZNS:CLAIM:alice:${validTestnetAddr}:sig123`);
    });

    it("throws on invalid name", () => {
      expect(() => zns.prepareClaim("INVALID", validTestnetAddr, 100)).toThrow("Invalid ZNS name");
    });
  });

  describe("prepareList / complete", () => {
    it("returns correct payload with camelCase param", () => {
      const pre = zns.prepareList("alice", 100_000, "t1testaddr", 1);
      expect(pre.payload).toBe("LIST:alice:100000:t1testaddr:1");
      expect(pre.payTaddr).toBe("t1testaddr"); // camelCase

      const post = pre.complete("dummySig");
      expect(post.memo).toBe("ZNS:LIST:alice:100000:t1testaddr:1:dummySig");
      expect(post.uri).toContain("memo=");
    });

    it("supports sovereign userPubkey", () => {
      const action = zns.prepareList("alice", 100_000, "t1testaddr", 1);
      const result = action.complete("dummySig", "mypk");
      expect(result.memo).toBe("ZNS:LIST:alice:100000:t1testaddr:1:dummySig:mypk");
    });
  });

  describe("prepareDelist / complete", () => {
    it("returns correct payload and memo", () => {
      const pre = zns.prepareDelist("alice", 2);
      expect(pre.payload).toBe("DELIST:alice:2");

      const post = pre.complete("dummySig");
      expect(post.memo).toBe("ZNS:DELIST:alice:2:dummySig");
    });
  });

  describe("prepareUpdate / complete", () => {
    it("returns correct payload and memo", () => {
      const pre = zns.prepareUpdate("alice", VALID_TESTNET_ADDR, 3);
      expect(pre.payload).toBe(`UPDATE:alice:${VALID_TESTNET_ADDR}:3`);

      const post = pre.complete("dummySig");
      expect(post.memo).toBe(`ZNS:UPDATE:alice:${VALID_TESTNET_ADDR}:3:dummySig`);
    });
  });

  describe("prepareBuy / complete", () => {
    it("returns correct payload and memo", () => {
      const pre = zns.prepareBuy("alice", VALID_TESTNET_ADDR, 100_000);
      expect(pre.payload).toBe(`BUY:alice:${VALID_TESTNET_ADDR}`);
      expect(pre.buyerAddress).toBe(VALID_TESTNET_ADDR); // camelCase

      const post = pre.complete("dummySig");
      expect(post.memo).toBe(`ZNS:BUY:alice:${VALID_TESTNET_ADDR}:100000:dummySig`);
    });

    it("supports sovereign userPubkey", () => {
      const action = zns.prepareBuy("alice", VALID_TESTNET_ADDR, 100_000);
      const result = action.complete("dummySig", "mypk");
      expect(result.memo).toBe(`ZNS:BUY:alice:${VALID_TESTNET_ADDR}:100000:dummySig:mypk`);
    });

    it("includes BUY_COMMISSION in the URI amount", () => {
      const action = zns.prepareBuy("alice", VALID_TESTNET_ADDR, 100_000);
      const result = action.complete("dummySig");
      expect(result.uri).toContain("amount=0.0001");
    });
  });

  describe("prepareRelease / complete", () => {
    it("returns correct payload and memo", () => {
      const pre = zns.prepareRelease("alice", 3);
      expect(pre.payload).toBe("RELEASE:alice:3");

      const post = pre.complete("dummySig");
      expect(post.memo).toBe("ZNS:RELEASE:alice:3:dummySig");
    });
  });

  describe("prepareSetPrice / complete", () => {
    it("returns correct payload and memo", () => {
      const pre = zns.prepareSetPrice([60000, 42500], 1);
      expect(pre.payload).toBe("SETPRICE:2:60000:42500:1");

      const post = pre.complete("dummySig");
      expect(post.memo).toBe("ZNS:SETPRICE:2:60000:42500:1:dummySig");
    });
  });
});

describe("isValidName", () => {
  it("accepts valid names", () => {
    const zns = new ZNS();
    expect(zns.isValidName("alice")).toBe(true);
    expect(zns.isValidName("bob123")).toBe(true);
    expect(zns.isValidName("a")).toBe(true);
  });

  it("rejects invalid names", () => {
    const zns = new ZNS();
    expect(zns.isValidName("")).toBe(false);
    expect(zns.isValidName("Alice")).toBe(false);
    expect(zns.isValidName("my-name")).toBe(false);
    expect(zns.isValidName("a".repeat(63))).toBe(false);
  });
});

describe("validatePayload", () => {
  let zns: ZNS;
  beforeEach(() => { zns = new ZNS(); });

  // ── Empty / malformed ───────────────────────────────────────────────────────

  it("rejects empty payload", () => {
    const r = zns.validatePayload("");
    expect(r.valid).toBe(false);
    expect(r.level).toBe("invalid");
    expect(r.action).toBe("");
    expect(r.canonicalAction).toBeNull();
  });

  it("rejects whitespace-only payload", () => {
    const r = zns.validatePayload("   ");
    expect(r.valid).toBe(false);
    expect(r.level).toBe("invalid");
  });

  it("rejects payload with no colon", () => {
    const r = zns.validatePayload("CLAIM");
    expect(r.valid).toBe(false);
    expect(r.level).toBe("invalid");
    expect(r.message).toContain("Missing colon");
  });

  it("returns unrecognized for unknown action", () => {
    const r = zns.validatePayload("FOO:bar:baz");
    expect(r.valid).toBe(false);
    expect(r.level).toBe("unrecognized");
    expect(r.action).toBe("FOO");
    expect(r.canonicalAction).toBeNull();
  });

  it("is case-insensitive for action", () => {
    const r = zns.validatePayload("claim:a:u1abc");
    expect(r.valid).toBe(true);
    expect(r.action).toBe("CLAIM");
    expect(r.canonicalAction).toBe("claim");
  });

  // ── CLAIM ─────────────────────────────────────────────────────────────────

  it("accepts valid CLAIM payload", () => {
    const r = zns.validatePayload(`CLAIM:alice:${VALID_TESTNET_ADDR}`);
    expect(r.valid).toBe(true);
    expect(r.action).toBe("CLAIM");
    expect(r.level).toBe("valid");
  });

  it("rejects CLAIM with wrong part count", () => {
    const r = zns.validatePayload("CLAIM:alice");
    expect(r.valid).toBe(false);
    expect(r.level).toBe("invalid");
    expect(r.message).toContain("Expected CLAIM");
  });

  it("rejects CLAIM with invalid name", () => {
    const r = zns.validatePayload(`CLAIM:UPPER:${VALID_TESTNET_ADDR}`);
    expect(r.valid).toBe(false);
    expect(r.message).toContain("lowercase");
  });

  it("rejects CLAIM with non-unified address", () => {
    const r = zns.validatePayload("CLAIM:alice:zs1notunified");
    expect(r.valid).toBe(false);
    expect(r.message).toContain("Invalid unified address");
  });

  // ── BUY ───────────────────────────────────────────────────────────────────

  it("accepts valid BUY payload", () => {
    const r = zns.validatePayload(`BUY:alice:${VALID_TESTNET_ADDR}`);
    expect(r.valid).toBe(true);
    expect(r.action).toBe("BUY");
  });

  it("rejects BUY with wrong part count", () => {
    const r = zns.validatePayload(`BUY:alice:${VALID_TESTNET_ADDR}:extra`);
    expect(r.valid).toBe(false);
    expect(r.level).toBe("invalid");
  });

  // ── UPDATE ────────────────────────────────────────────────────────────────

  it("accepts valid UPDATE payload", () => {
    const r = zns.validatePayload(`UPDATE:alice:${VALID_TESTNET_ADDR}:1`);
    expect(r.valid).toBe(true);
    expect(r.action).toBe("UPDATE");
  });

  it("rejects UPDATE with non-numeric nonce", () => {
    const r = zns.validatePayload(`UPDATE:alice:${VALID_TESTNET_ADDR}:abc`);
    expect(r.valid).toBe(false);
    expect(r.message).toContain("Nonce must be a whole number");
  });

  it("rejects UPDATE with wrong part count", () => {
    const r = zns.validatePayload(`UPDATE:alice:${VALID_TESTNET_ADDR}`);
    expect(r.valid).toBe(false);
    expect(r.message).toContain("Expected UPDATE");
  });

  // ── LIST ──────────────────────────────────────────────────────────────────

  it("accepts valid LIST payload", () => {
    const r = zns.validatePayload("LIST:alice:100000000:t1test123456789012345678:1");
    expect(r.valid).toBe(true);
    expect(r.action).toBe("LIST");
  });

  it("rejects LIST with wrong part count", () => {
    const r = zns.validatePayload("LIST:alice:100000000:1");
    expect(r.valid).toBe(false);
    expect(r.message).toContain("Expected LIST");
  });

  it("rejects LIST with negative price", () => {
    const r = zns.validatePayload("LIST:alice:-1:t1test:1");
    expect(r.valid).toBe(false);
    expect(r.message).toContain("positive whole number in zats");
  });

  it("rejects LIST with zero price", () => {
    const r = zns.validatePayload("LIST:alice:0:t1test:1");
    expect(r.valid).toBe(false);
    expect(r.message).toContain("positive whole number in zats");
  });

  // ── DELIST ─────────────────────────────────────────────────────────────────

  it("accepts valid DELIST payload", () => {
    const r = zns.validatePayload("DELIST:alice:2");
    expect(r.valid).toBe(true);
    expect(r.action).toBe("DELIST");
  });

  it("rejects DELIST with wrong part count", () => {
    const r = zns.validatePayload("DELIST:alice");
    expect(r.valid).toBe(false);
    expect(r.message).toContain("Expected DELIST");
  });

  // ── RELEASE ───────────────────────────────────────────────────────────────

  it("accepts valid RELEASE payload", () => {
    const r = zns.validatePayload("RELEASE:alice:3");
    expect(r.valid).toBe(true);
    expect(r.action).toBe("RELEASE");
  });

  it("rejects RELEASE with wrong part count", () => {
    const r = zns.validatePayload("RELEASE:alice");
    expect(r.valid).toBe(false);
    expect(r.message).toContain("Expected RELEASE");
  });

  // ── Name length edge cases ─────────────────────────────────────────────────

  it("accepts 62-char name", () => {
    const name62 = "a".repeat(62);
    const r = zns.validatePayload(`CLAIM:${name62}:${VALID_TESTNET_ADDR}`);
    expect(r.valid).toBe(true);
  });

  it("rejects 63-char name", () => {
    const name63 = "a".repeat(63);
    const r = zns.validatePayload(`CLAIM:${name63}:${VALID_TESTNET_ADDR}`);
    expect(r.valid).toBe(false);
    expect(r.message).toContain("62 chars");
  });

  it("rejects empty name", () => {
    const r = zns.validatePayload(`CLAIM::${VALID_TESTNET_ADDR}`);
    expect(r.valid).toBe(false);
    expect(r.message).toContain("lowercase");
  });
});

describe("claimCost", () => {
  it("returns cost based on pricing tiers", () => {
    const zns = new ZNS();
    expect(zns.claimCost(1, mockStatus.pricing)).toBe(600_000_000);
    expect(zns.claimCost(3, mockStatus.pricing)).toBe(300_000_000);
    expect(zns.claimCost(5, mockStatus.pricing)).toBe(75_000_000);
  });

  it("clamps long names to last tier", () => {
    const zns = new ZNS();
    expect(zns.claimCost(7, mockStatus.pricing)).toBe(50_000_000);
    expect(zns.claimCost(62, mockStatus.pricing)).toBe(50_000_000);
  });

  it("returns null when no tiers", () => {
    const zns = new ZNS();
    const emptyPricing = { ...mockStatus.pricing, tiers: [] };
    expect(zns.claimCost(1, emptyPricing)).toBeNull();
  });

  it("BUY_COMMISSION is 10,000 zats", () => {
    expect(BUY_COMMISSION).toBe(10_000);
  });

  it("listCommission returns 10% of minimum tier", () => {
    const zns = new ZNS();
    expect(zns.listCommission(mockStatus.pricing)).toBe(5_000_000);
  });

  it("listCommission returns null when no tiers", () => {
    const zns = new ZNS();
    const emptyPricing = { ...mockStatus.pricing, tiers: [] };
    expect(zns.listCommission(emptyPricing)).toBeNull();
  });
});

describe("parseZip321Uri", () => {
  it("parses a full URI", () => {
    const zns = new ZNS();
    const parts = zns.parseZip321Uri("zcash:utest1addr?amount=1.5&memo=dGVzdA");
    expect(parts.address).toBe("utest1addr");
    expect(parts.amount).toBe("1.5");
    expect(parts.memoRaw).toBe("dGVzdA");
  });

  it("parses address-only URI", () => {
    const zns = new ZNS();
    const parts = zns.parseZip321Uri("zcash:utest1addr");
    expect(parts.address).toBe("utest1addr");
    expect(parts.amount).toBe("");
  });
});
