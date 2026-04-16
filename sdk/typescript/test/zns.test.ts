import { describe, it, expect, vi, beforeEach } from "vitest";
import { ZNS, DEFAULT_URL, TESTNET_UIVK } from "../src/zns.js";

// Valid testnet unified address (bech32m format)
const VALID_TESTNET_ADDR = "utest1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";

const mockStatus = {
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

describe("ZNS.create", () => {
  it("connects and pins state from status()", async () => {
    globalThis.fetch = mockRpc(mockStatus);
    const zns = await ZNS.create();
    expect(zns.verified).toBe(true);
    expect(zns.adminPubkey).toBe(mockStatus.admin_pubkey);
    expect(zns.pricing).toEqual(mockStatus.pricing);
    expect(zns.registryAddress).toBe(VALID_TESTNET_ADDR);
  });

  it("throws on UIVK mismatch", async () => {
    globalThis.fetch = mockRpc({ ...mockStatus, uivk: "wrong" });
    await expect(ZNS.create()).rejects.toThrow("UIVK mismatch");
  });

  it("skips UIVK check with skipVerify", async () => {
    globalThis.fetch = mockRpc({ ...mockStatus, uivk: "unknown" });
    const zns = await ZNS.create({ skipVerify: true });
    expect(zns.verified).toBe(false);
  });

  it("uses custom url", async () => {
    globalThis.fetch = mockRpc(mockStatus);
    const zns = await ZNS.create({ url: "http://localhost:3000" });
    expect(zns.verified).toBe(true);
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
      listing: { name: "alice", price: 100_000, nonce: 1, txid: "tx2", height: 200, signature: "sig1", pubkey: null },
    };
    globalThis.fetch = mockRpcSequence([mockStatus, reg]);

    const zns = await ZNS.create();
    const result = await zns.resolveName("alice");

    expect(result).not.toBeNull();
    if (result) {
      expect(result.name).toBe("alice");
      expect(result.address).toBe("utest1addr");
      expect(result.listing).not.toBeNull();
      expect(result.listing?.name).toBe("alice");
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
    globalThis.fetch = mockRpcSequence([mockStatus, reg]);

    const zns = await ZNS.create();
    const result = await zns.resolveName("alice");

    if (result) {
      expect(result.pubkey).toBe("differentpubkeybase64=");
      expect(result.listing).toBeNull();
    }
  });

  it("returns null for unknown name", async () => {
    globalThis.fetch = mockRpcSequence([mockStatus, null]);
    const zns = await ZNS.create();
    const result = await zns.resolveName("doesnotexist");
    expect(result).toBeNull();
  });
});

describe("isAvailable", () => {
  it("returns true for unregistered name", async () => {
    globalThis.fetch = mockRpcSequence([mockStatus, null]);
    const zns = await ZNS.create();
    expect(await zns.isAvailable("doesnotexist")).toBe(true);
  });

  it("returns false for registered name", async () => {
    const reg = {
      name: "alice", address: "u1", txid: "tx1", height: 100,
      nonce: 0, signature: null, last_action: "CLAIM", pubkey: null, listing: null,
    };
    globalThis.fetch = mockRpcSequence([mockStatus, reg]);
    const zns = await ZNS.create();
    expect(await zns.isAvailable("alice")).toBe(false);
  });
});

describe("listings", () => {
  it("returns raw listings", async () => {
    const listings = {
      listings: [
        { name: "bob", price: 100_000, nonce: 1, txid: "tx1", height: 200, signature: "sig1", pubkey: null },
      ],
    };
    globalThis.fetch = mockRpcSequence([mockStatus, listings]);
    const zns = await ZNS.create();
    const result = await zns.listings();
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("bob");
    expect(result[0].pubkey).toBeNull();
  });
});

describe("verification", () => {
  it("verifyListing returns false when no admin_pubkey", async () => {
    globalThis.fetch = mockRpc(mockStatus);
    const zns = await ZNS.create();
    // @ts-expect-error - accessing private field for test
    zns._adminPubkey = null;
    
    const listing = { name: "bob", price: 100_000, nonce: 1, txid: "tx1", height: 200, signature: "sig1", pubkey: null };
    const result = await zns.verifyListing(listing);
    expect(result).toBe(false);
  });

  it("verifyRegistration returns false when no signature", async () => {
    globalThis.fetch = mockRpc(mockStatus);
    const zns = await ZNS.create();
    
    const reg = { name: "alice", address: "u1", txid: "tx1", height: 100, nonce: 0, signature: null, last_action: "CLAIM", pubkey: null };
    const result = await zns.verifyRegistration(reg);
    expect(result).toBe(false);
  });
});

describe("action flows", () => {
  let zns: ZNS;

  beforeEach(async () => {
    globalThis.fetch = mockRpc(mockStatus);
    zns = await ZNS.create();
  });

  describe("prepareClaim / completeClaim", () => {
    const validTestnetAddr = "utest1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
    
    it("prepareClaim returns payload, cost, and complete method", () => {
      const result = zns.prepareClaim("alice", validTestnetAddr);
      expect(result.payload).toBe(`CLAIM:alice:${validTestnetAddr}`);
      expect(result.cost).toBe(75_000_000);
      expect(typeof result.complete).toBe("function");
    });

    it("complete returns memo and uri", () => {
      const action = zns.prepareClaim("alice", validTestnetAddr);
      const result = action.complete("sig123", "pubkey456");
      expect(result.memo).toBe(`ZNS:CLAIM:alice:${validTestnetAddr}:sig123:pubkey456`);
      expect(result.uri).toContain("memo=");
    });

    it("complete without userPubkey omits it", () => {
      const action = zns.prepareClaim("alice", validTestnetAddr);
      const result = action.complete("sig123");
      expect(result.memo).toBe(`ZNS:CLAIM:alice:${validTestnetAddr}:sig123`);
    });

    it("throws on invalid name", () => {
      expect(() => zns.prepareClaim("INVALID", validTestnetAddr)).toThrow("Invalid ZNS name");
    });
  });

  describe("prepareList / complete", () => {
    it("returns correct payload and memo", () => {
      const pre = zns.prepareList("alice", 100_000, 1);
      expect(pre.payload).toBe("LIST:alice:100000:1");

      const post = pre.complete("dummySig");
      expect(post.memo).toBe("ZNS:LIST:alice:100000:1:dummySig");
      expect(post.uri).toContain("memo=");
    });

    it("supports sovereign userPubkey", () => {
      const action = zns.prepareList("alice", 100_000, 1);
      const result = action.complete("dummySig", "mypk");
      expect(result.memo).toBe("ZNS:LIST:alice:100000:1:dummySig:mypk");
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
      const pre = zns.prepareBuy("alice", VALID_TESTNET_ADDR);
      expect(pre.payload).toBe(`BUY:alice:${VALID_TESTNET_ADDR}`);

      const post = pre.complete("dummySig");
      expect(post.memo).toBe(`ZNS:BUY:alice:${VALID_TESTNET_ADDR}:dummySig`);
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
  let zns: ZNS;

  beforeEach(async () => {
    globalThis.fetch = mockRpc(mockStatus);
    zns = await ZNS.create();
  });

  it("accepts valid names", () => {
    expect(zns.isValidName("alice")).toBe(true);
    expect(zns.isValidName("bob123")).toBe(true);
    expect(zns.isValidName("a")).toBe(true);
  });

  it("rejects invalid names", () => {
    expect(zns.isValidName("")).toBe(false);
    expect(zns.isValidName("Alice")).toBe(false);
    expect(zns.isValidName("my-name")).toBe(false);
    expect(zns.isValidName("a".repeat(63))).toBe(false);
  });
});

describe("claimCost", () => {
  let zns: ZNS;

  beforeEach(async () => {
    globalThis.fetch = mockRpc(mockStatus);
    zns = await ZNS.create();
  });

  it("returns cost based on pricing tiers", () => {
    expect(zns.claimCost(1)).toBe(600_000_000);
    expect(zns.claimCost(3)).toBe(300_000_000);
    expect(zns.claimCost(5)).toBe(75_000_000);
  });

  it("clamps long names to last tier", () => {
    expect(zns.claimCost(7)).toBe(50_000_000);
    expect(zns.claimCost(62)).toBe(50_000_000);
  });

  it("returns null when no pricing", async () => {
    globalThis.fetch = mockRpc({ ...mockStatus, pricing: null });
    const znsNoPrice = await ZNS.create();
    expect(znsNoPrice.claimCost(1)).toBeNull();
  });
});

describe("parseZip321Uri", () => {
  let zns: ZNS;

  beforeEach(async () => {
    globalThis.fetch = mockRpc(mockStatus);
    zns = await ZNS.create();
  });

  it("parses a full URI", () => {
    const parts = zns.parseZip321Uri("zcash:utest1addr?amount=1.5&memo=dGVzdA");
    expect(parts.address).toBe("utest1addr");
    expect(parts.amount).toBe("1.5");
    expect(parts.memoRaw).toBe("dGVzdA");
  });

  it("parses address-only URI", () => {
    const parts = zns.parseZip321Uri("zcash:utest1addr");
    expect(parts.address).toBe("utest1addr");
    expect(parts.amount).toBe("");
  });
});
