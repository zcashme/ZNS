import { describe, it, expect, vi, beforeEach } from "vitest";
import { ZNS, DEFAULT_URL, TESTNET_UIVK } from "../src/zns.js";

const mockStatus = {
  synced_height: 3902500,
  admin_pubkey: "YCsjrC6I8UFsWwGJIpCQx9FI98Q4g3E7+8CQ3E8M9OE=",
  uivk: TESTNET_UIVK,
  address: "utest1registry",
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
    expect(zns.registryAddress).toBe("utest1registry");
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

describe("resolve", () => {
  it("returns resolve result with listing", async () => {
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
    const result = await zns.resolve("alice");

    expect(result).not.toBeNull();
    if (result && !Array.isArray(result)) {
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
    const result = await zns.resolve("alice");

    if (result && !Array.isArray(result)) {
      expect(result.pubkey).toBe("differentpubkeybase64=");
      expect(result.listing).toBeNull();
    }
  });

  it("returns null for unknown name", async () => {
    globalThis.fetch = mockRpcSequence([mockStatus, null]);
    const zns = await ZNS.create();
    const result = await zns.resolve("doesnotexist");
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
    it("prepareClaim returns payload, cost, uri", () => {
      const result = zns.prepareClaim("alice", "utest1addr");
      expect(result.payload).toBe("CLAIM:alice:utest1addr");
      expect(result.cost).toBe(75_000_000);
      expect(result.uri).toContain("zcash:utest1registry");
    });

    it("completeClaim returns memo and uri", () => {
      const result = zns.completeClaim("alice", "utest1addr", "sig123", "pubkey456");
      expect(result.memo).toBe("ZNS:CLAIM:alice:utest1addr:sig123:pubkey456");
      expect(result.uri).toContain("memo=");
    });

    it("completeClaim without userPubkey omits it", () => {
      const result = zns.completeClaim("alice", "utest1addr", "sig123");
      expect(result.memo).toBe("ZNS:CLAIM:alice:utest1addr:sig123");
    });

    it("throws on invalid name", () => {
      expect(() => zns.prepareClaim("INVALID", "utest1addr")).toThrow("Invalid ZNS name");
    });
  });

  describe("prepareList / completeList", () => {
    it("returns correct payload and memo", () => {
      const pre = zns.prepareList("alice", 100_000, 1);
      expect(pre.payload).toBe("LIST:alice:100000:1");

      const post = zns.completeList("alice", 100_000, 1, "sig1");
      expect(post.memo).toBe("ZNS:LIST:alice:100000:1:sig1");
      expect(post.uri).toContain("memo=");
    });

    it("supports sovereign userPubkey", () => {
      const post = zns.completeList("alice", 100_000, 1, "sig1", "mypk");
      expect(post.memo).toBe("ZNS:LIST:alice:100000:1:sig1:mypk");
    });
  });

  describe("prepareDelist / completeDelist", () => {
    it("returns correct payload and memo", () => {
      const pre = zns.prepareDelist("alice", 2);
      expect(pre.payload).toBe("DELIST:alice:2");

      const post = zns.completeDelist("alice", 2, "sig2");
      expect(post.memo).toBe("ZNS:DELIST:alice:2:sig2");
    });
  });

  describe("prepareUpdate / completeUpdate", () => {
    it("returns correct payload and memo", () => {
      const pre = zns.prepareUpdate("alice", "utest1new", 3);
      expect(pre.payload).toBe("UPDATE:alice:utest1new:3");

      const post = zns.completeUpdate("alice", "utest1new", 3, "sig3");
      expect(post.memo).toBe("ZNS:UPDATE:alice:utest1new:3:sig3");
    });
  });

  describe("prepareBuy / completeBuy", () => {
    it("returns correct payload and memo", () => {
      const pre = zns.prepareBuy("alice", "utest1buyer");
      expect(pre.payload).toBe("BUY:alice:utest1buyer");

      const post = zns.completeBuy("alice", "utest1buyer", "sig4");
      expect(post.memo).toBe("ZNS:BUY:alice:utest1buyer:sig4");
    });
  });

  describe("prepareRelease / completeRelease", () => {
    it("returns correct payload and memo", () => {
      const pre = zns.prepareRelease("alice", 3);
      expect(pre.payload).toBe("RELEASE:alice:3");

      const post = zns.completeRelease("alice", 3, "sig5");
      expect(post.memo).toBe("ZNS:RELEASE:alice:3:sig5");
    });
  });

  describe("prepareSetPrice / completeSetPrice", () => {
    it("returns correct payload and memo", () => {
      const pre = zns.prepareSetPrice([60000, 42500], 1);
      expect(pre.payload).toBe("SETPRICE:2:60000:42500:1");

      const post = zns.completeSetPrice([60000, 42500], 1, "sig6");
      expect(post.memo).toBe("ZNS:SETPRICE:2:60000:42500:1:sig6");
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
