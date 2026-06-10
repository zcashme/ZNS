import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as ed25519 from "@noble/ed25519";
import { blake2b } from "@noble/hashes/blake2.js";
import { ZNS } from "../src/zns.js";
import type {
  RegistrationWithProof,
  MerkleProof,
  LastAction,
} from "../src/types.js";

const VALID_TESTNET_UA = "utest100qlkeru5c3m5kfrwe2hsmcfzmusreaza2prdyelg2kd2tr2842nceq952vay3gpmgky09fgft4z57h4z2zqzz5rcwgd4q90u54ek5yyca4s6e6y2jja9sww27kzedzznjcupcu0svq2exvq995c0lhl5zm53g4ksnm2xuwt3snv4dgh";
const VALID_MAINNET_UA = "u1q8g0h9cn2x4eq8jd7k0d5y3zf6vhb5w4xj9tz3m5p6r2s1t0u7v8w9x0y1z";
const VALID_TESTNET_TADDR = "tmqY61Gp3B7Pz3ev12NRFzWxJz1yB28Gfkfi";

describe("ZNS", () => {
  let zns: ZNS;

  beforeEach(() => {
    zns = new ZNS();
  });

  describe("constructor", () => {
    it("defaults to testnet", () => {
      const z = new ZNS();
      expect(z.network).toBe("testnet");
    });

    it("accepts network option", () => {
      const z = new ZNS({ network: "mainnet" });
      expect(z.network).toBe("mainnet");
    });

    it("accepts custom url", () => {
      const z = new ZNS({ url: "https://custom.example.com" });
      expect(z.url).toBe("https://custom.example.com");
    });
  });

  describe("isValidName", () => {
    it("accepts valid names", () => {
      expect(zns.isValidName("alice")).toBe(true);
      expect(zns.isValidName("bob123")).toBe(true);
      expect(zns.isValidName("a")).toBe(true);
      expect(zns.isValidName("a".repeat(62))).toBe(true);
    });

    it("rejects invalid names", () => {
      expect(zns.isValidName("")).toBe(false);
      expect(zns.isValidName("Alice")).toBe(false);
      expect(zns.isValidName("my-name")).toBe(false);
      expect(zns.isValidName("a".repeat(63))).toBe(false);
    });
  });

  describe("normalizeName", () => {
    it("lowercases and strips .zcash/.zec suffix in any case", () => {
      expect(zns.normalizeName("alice")).toBe("alice");
      expect(zns.normalizeName("Alice.zcash")).toBe("alice");
      expect(zns.normalizeName("alice.zec")).toBe("alice");
      expect(zns.normalizeName("aLice.Zec")).toBe("alice");
      expect(zns.normalizeName("alice.ZCASH")).toBe("alice");
      expect(zns.normalizeName("ALICE")).toBe("alice");
      expect(zns.normalizeName("  alice.Zec  ")).toBe("alice");
    });

    it("does not strip non-suffix lookalikes", () => {
      expect(zns.normalizeName("zec")).toBe("zec");
      expect(zns.normalizeName("zcash")).toBe("zcash");
      expect(zns.normalizeName("alice.eth")).toBe("alice.eth");
      expect(zns.normalizeName("alice.")).toBe("alice.");
    });

    it("strips only one suffix", () => {
      expect(zns.normalizeName("alice.zec.zec")).toBe("alice.zec");
      expect(zns.normalizeName(".zec")).toBe("");
    });
  });

  describe("resolveName normalization", () => {
    afterEach(() => {
      vi.unstubAllGlobals();
    });

    const stubResolve = () => {
      const bodies: Array<Record<string, unknown>> = [];
      vi.stubGlobal(
        "fetch",
        vi.fn(async (_url: string, init: { body: string }) => {
          const body = JSON.parse(init.body);
          bodies.push(body);
          return {
            ok: true,
            json: async () => ({
              result: {
                name: "alice",
                address: VALID_TESTNET_UA,
                txid: "ab".repeat(32),
                height: 100,
                nonce: 0,
                last_action: "CLAIM",
              },
            }),
          };
        }),
      );
      return bodies;
    };

    it("sends the normalized name as the query", async () => {
      const bodies = stubResolve();
      for (const input of ["Alice.zcash", "alice.zec", "aLice.Zec", "alice.ZCASH"]) {
        const reg = await zns.resolveName(input);
        expect(reg?.name).toBe("alice");
      }
      expect(bodies.map((b) => (b.params as { query: string }).query)).toEqual([
        "alice",
        "alice",
        "alice",
        "alice",
      ]);
    });

    it("returns null for invalid names without hitting the server", async () => {
      const fetchSpy = vi.fn();
      vi.stubGlobal("fetch", fetchSpy);
      expect(await zns.resolveName("alice.eth")).toBeNull();
      expect(await zns.resolveName("alice.zec.zec")).toBeNull();
      expect(await zns.resolveName(".zec")).toBeNull();
      expect(await zns.resolveName("")).toBeNull();
      expect(await zns.resolveNameWithProof("alice.eth")).toBeNull();
      expect(await zns.isAvailable("alice.eth")).toBe(false);
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("isAvailable checks the normalized name", async () => {
      const bodies = stubResolve();
      expect(await zns.isAvailable("Alice.zec")).toBe(false);
      expect((bodies[0].params as { query: string }).query).toBe("alice");
    });
  });

  describe("isValidUnifiedAddress", () => {
    it("accepts valid testnet UA", () => {
      expect(zns.isValidUnifiedAddress(VALID_TESTNET_UA)).toBe(true);
    });

    it("accepts valid mainnet UA", () => {
      expect(zns.isValidUnifiedAddress(VALID_MAINNET_UA)).toBe(true);
    });

    it("rejects invalid addresses", () => {
      expect(zns.isValidUnifiedAddress("")).toBe(false);
      expect(zns.isValidUnifiedAddress("notanaddress")).toBe(false);
      expect(zns.isValidUnifiedAddress("zs1abc...")).toBe(false);
    });
  });

  describe("isValidTransparentAddress", () => {
    it("accepts valid testnet tm address", () => {
      expect(zns.isValidTransparentAddress(VALID_TESTNET_TADDR)).toBe(true);
    });

    it("rejects invalid addresses", () => {
      expect(zns.isValidTransparentAddress("")).toBe(false);
      expect(zns.isValidTransparentAddress("notanaddress")).toBe(false);
      expect(zns.isValidTransparentAddress("u1abc...")).toBe(false);
    });
  });

  describe("validatePayload", () => {
    describe("CLAIM", () => {
      it("accepts valid payload", () => {
        const result = zns.validatePayload(`CLAIM:alice:${VALID_TESTNET_UA}`);
        expect(result.valid).toBe(true);
        expect(result.action).toBe("CLAIM");
        expect(result.level).toBe("valid");
      });

      it("rejects invalid name", () => {
        const result = zns.validatePayload(`CLAIM:UPPER:${VALID_TESTNET_UA}`);
        expect(result.valid).toBe(false);
        expect(result.message).toContain("lowercase");
      });

      it("rejects invalid UA", () => {
        const result = zns.validatePayload("CLAIM:alice:zs1notvalid");
        expect(result.valid).toBe(false);
        expect(result.message).toContain("unified address");
      });

      it("rejects wrong part count", () => {
        const result = zns.validatePayload(`CLAIM:alice:${VALID_TESTNET_UA}:extra`);
        expect(result.valid).toBe(false);
        expect(result.message).toContain("Expected CLAIM");
      });
    });

    describe("BUY", () => {
      it("accepts valid payload", () => {
        const result = zns.validatePayload(`BUY:alice:${VALID_TESTNET_UA}`);
        expect(result.valid).toBe(true);
        expect(result.action).toBe("BUY");
      });
    });

    describe("UPDATE", () => {
      it("accepts valid payload", () => {
        const result = zns.validatePayload(`UPDATE:alice:${VALID_TESTNET_UA}:1`);
        expect(result.valid).toBe(true);
        expect(result.action).toBe("UPDATE");
      });

      it("rejects non-numeric nonce", () => {
        const result = zns.validatePayload(`UPDATE:alice:${VALID_TESTNET_UA}:abc`);
        expect(result.valid).toBe(false);
        expect(result.message).toContain("whole number");
      });
    });

    describe("LIST", () => {
      it("accepts valid payload with t-addr", () => {
        const result = zns.validatePayload(`LIST:alice:100000000:${VALID_TESTNET_TADDR}:1`);
        expect(result.valid).toBe(true);
        expect(result.action).toBe("LIST");
      });

      it("rejects zero price", () => {
        const result = zns.validatePayload(`LIST:alice:0:${VALID_TESTNET_TADDR}:1`);
        expect(result.valid).toBe(false);
        expect(result.message).toContain("positive whole number");
      });

      it("rejects negative price", () => {
        const result = zns.validatePayload(`LIST:alice:-1:${VALID_TESTNET_TADDR}:1`);
        expect(result.valid).toBe(false);
      });
    });

    describe("DELIST", () => {
      it("accepts valid payload", () => {
        const result = zns.validatePayload("DELIST:alice:2");
        expect(result.valid).toBe(true);
        expect(result.action).toBe("DELIST");
      });
    });

    describe("RELEASE", () => {
      it("accepts valid payload", () => {
        const result = zns.validatePayload("RELEASE:alice:3");
        expect(result.valid).toBe(true);
        expect(result.action).toBe("RELEASE");
      });
    });

    describe("case insensitivity", () => {
      it("accepts lowercase action", () => {
        const result = zns.validatePayload(`claim:alice:${VALID_TESTNET_UA}`);
        expect(result.valid).toBe(true);
        expect(result.action).toBe("CLAIM");
      });

      it("accepts mixed case action", () => {
        const result = zns.validatePayload(`ClAiM:alice:${VALID_TESTNET_UA}`);
        expect(result.valid).toBe(true);
        expect(result.action).toBe("CLAIM");
      });
    });

    describe("error cases", () => {
      it("rejects empty payload", () => {
        const result = zns.validatePayload("");
        expect(result.valid).toBe(false);
        expect(result.level).toBe("invalid");
      });

      it("rejects unknown action", () => {
        const result = zns.validatePayload("FOO:bar:baz");
        expect(result.valid).toBe(false);
        expect(result.level).toBe("unrecognized");
      });

      it("rejects missing colon", () => {
        const result = zns.validatePayload("CLAIM");
        expect(result.valid).toBe(false);
        expect(result.message).toContain("Missing colon");
      });
    });
  });

  describe("verifySignature", () => {
    it("accepts a valid signature", async () => {
      const sk = ed25519.utils.randomPrivateKey();
      const pk = await ed25519.getPublicKeyAsync(sk);
      const payload = `CLAIM:alice:${VALID_TESTNET_UA}`;
      const signature = await ed25519.signAsync(new TextEncoder().encode(payload), sk);
      const pubkey = Buffer.from(pk).toString("base64");
      const sigBase64 = Buffer.from(signature).toString("base64");

      const result = await zns.verifySignature(payload, sigBase64, pubkey);
      expect(result).toBe(true);
    });

    it("rejects signature with wrong pubkey", async () => {
      const sk = ed25519.utils.randomPrivateKey();
      const wrongSk = ed25519.utils.randomPrivateKey();
      const pk = await ed25519.getPublicKeyAsync(sk);
      const wrongPk = await ed25519.getPublicKeyAsync(wrongSk);
      const payload = `CLAIM:alice:${VALID_TESTNET_UA}`;
      const signature = await ed25519.signAsync(new TextEncoder().encode(payload), sk);
      const wrongPubkey = Buffer.from(wrongPk).toString("base64");
      const sigBase64 = Buffer.from(signature).toString("base64");

      const result = await zns.verifySignature(payload, sigBase64, wrongPubkey);
      expect(result).toBe(false);
    });

    it("rejects signature on tampered payload", async () => {
      const sk = ed25519.utils.randomPrivateKey();
      const pk = await ed25519.getPublicKeyAsync(sk);
      const payload = `CLAIM:alice:${VALID_TESTNET_UA}`;
      const tamperedPayload = `CLAIM:bob:${VALID_TESTNET_UA}`;
      const signature = await ed25519.signAsync(new TextEncoder().encode(payload), sk);
      const pubkey = Buffer.from(pk).toString("base64");
      const sigBase64 = Buffer.from(signature).toString("base64");

      const result = await zns.verifySignature(tamperedPayload, sigBase64, pubkey);
      expect(result).toBe(false);
    });

    it("rejects malformed signature", async () => {
      const sk = ed25519.utils.randomPrivateKey();
      const pk = await ed25519.getPublicKeyAsync(sk);
      const payload = `CLAIM:alice:${VALID_TESTNET_UA}`;
      const pubkey = Buffer.from(pk).toString("base64");

      const result = await zns.verifySignature(payload, "notavalidb64", pubkey);
      expect(result).toBe(false);
    });

    it("rejects malformed pubkey", async () => {
      const sk = ed25519.utils.randomPrivateKey();
      const payload = `CLAIM:alice:${VALID_TESTNET_UA}`;
      const signature = await ed25519.signAsync(new TextEncoder().encode(payload), sk);
      const sigBase64 = Buffer.from(signature).toString("base64");

      const result = await zns.verifySignature(payload, sigBase64, "notavalidb64");
      expect(result).toBe(false);
    });

    it("accepts valid signature for all action types", async () => {
      const sk = ed25519.utils.randomPrivateKey();
      const pk = await ed25519.getPublicKeyAsync(sk);
      const pubkey = Buffer.from(pk).toString("base64");
      const actions = [
        `CLAIM:alice:${VALID_TESTNET_UA}`,
        `BUY:alice:${VALID_TESTNET_UA}`,
        `UPDATE:alice:${VALID_TESTNET_UA}:1`,
        `LIST:alice:100000000:${VALID_TESTNET_TADDR}:1`,
        `DELIST:alice:1`,
        `RELEASE:alice:1`,
      ];

      for (const payload of actions) {
        const signature = await ed25519.signAsync(new TextEncoder().encode(payload), sk);
        const sigBase64 = Buffer.from(signature).toString("base64");
        const result = await zns.verifySignature(payload, sigBase64, pubkey);
        expect(result).toBe(true);
      }
    });
  });

  describe("prepareClaim", () => {
    it("builds valid claim payload", () => {
      const claim = zns.prepareClaim("alice", VALID_TESTNET_UA, 1000);
      expect(claim.payload).toBe(`CLAIM:alice:${VALID_TESTNET_UA}`);
      expect(claim.name).toBe("alice");
      expect(claim.address).toBe(VALID_TESTNET_UA);
      expect(claim.cost).toBe(1000);
    });

    it("complete() builds the memo", async () => {
      const claim = zns.prepareClaim("alice", VALID_TESTNET_UA, 1000);
      const sk = ed25519.utils.randomPrivateKey();
      const pk = await ed25519.getPublicKeyAsync(sk);
      const signature = await ed25519.signAsync(new TextEncoder().encode(claim.payload), sk);
      const sigBase64 = Buffer.from(signature).toString("base64");

      const { memo, uri } = claim.complete(sigBase64);
      expect(memo).toBe(`ZNS:CLAIM:alice:${VALID_TESTNET_UA}:${sigBase64}`);
      expect(memo).not.toContain(":undefined");
    });

    it("normalizes the name before building the payload", () => {
      const claim = zns.prepareClaim("  ALICE.Zec ", VALID_TESTNET_UA, 1000);
      expect(claim.name).toBe("alice");
      expect(claim.payload).toBe(`CLAIM:alice:${VALID_TESTNET_UA}`);
      const { memo } = claim.complete("SIGB64");
      expect(memo).toBe(`ZNS:CLAIM:alice:${VALID_TESTNET_UA}:SIGB64`);
    });

    it("throws on invalid name", () => {
      expect(() => zns.prepareClaim("alice.eth", VALID_TESTNET_UA, 1000)).toThrow("Invalid ZNS name");
      expect(() => zns.prepareClaim("my-name", VALID_TESTNET_UA, 1000)).toThrow("Invalid ZNS name");
    });

    it("throws on invalid address", () => {
      expect(() => zns.prepareClaim("alice", "notvalid", 1000)).toThrow("Invalid Zcash Unified Address");
    });
  });

  describe("prepareList", () => {
    it("builds valid list payload", () => {
      const list = zns.prepareList("alice", 100000000, VALID_TESTNET_TADDR, 1, 10);
      expect(list.payload).toBe(`LIST:alice:100000000:${VALID_TESTNET_TADDR}:1`);
      expect(list.commission).toBe(10);
    });

    it("normalizes the name before building the payload", () => {
      const list = zns.prepareList("Alice.zcash", 100000000, VALID_TESTNET_TADDR, 1, 10);
      expect(list.name).toBe("alice");
      expect(list.payload).toBe(`LIST:alice:100000000:${VALID_TESTNET_TADDR}:1`);
    });

    it("throws on invalid name", () => {
      expect(() => zns.prepareList("alice.eth", 100000000, VALID_TESTNET_TADDR, 1, 10)).toThrow("Invalid ZNS name");
    });
  });

  describe("prepareUpdate", () => {
    it("builds valid update payload", () => {
      const update = zns.prepareUpdate("alice", VALID_TESTNET_UA, 2);
      expect(update.payload).toBe(`UPDATE:alice:${VALID_TESTNET_UA}:2`);
    });

    it("throws on invalid name", () => {
      expect(() => zns.prepareUpdate("alice.eth", VALID_TESTNET_UA, 2)).toThrow("Invalid ZNS name");
    });

    it("throws on invalid address", () => {
      expect(() => zns.prepareUpdate("alice", "notvalid", 2)).toThrow("Invalid Zcash Unified Address");
    });
  });

  describe("claimCost", () => {
    it("returns correct tier for name length", () => {
      const pricing = { tiers: [100, 200, 300, 500, 1000] };
      expect(zns.claimCost(1, pricing)).toBe(100);
      expect(zns.claimCost(2, pricing)).toBe(200);
      expect(zns.claimCost(3, pricing)).toBe(300);
      expect(zns.claimCost(4, pricing)).toBe(500);
      expect(zns.claimCost(62, pricing)).toBe(1000);
    });

    it("clamps to max tier for long names", () => {
      const pricing = { tiers: [100, 200, 300] };
      expect(zns.claimCost(100, pricing)).toBe(300);
    });

    it("returns null for empty tiers", () => {
      expect(zns.claimCost(5, { tiers: [] })).toBeNull();
    });
  });

  describe("listCommission", () => {
    it("returns 10% of minimum tier", () => {
      const pricing = { tiers: [100, 200, 300] };
      expect(zns.listCommission(pricing)).toBe(10);
    });

    it("returns null for empty tiers", () => {
      expect(zns.listCommission({ tiers: [] })).toBeNull();
    });
  });

  describe("parseZip321Uri", () => {
    it("parses address and amount", () => {
      const result = zns.parseZip321Uri("zcash:u1abc?amount=1.5&memo=abc123");
      expect(result.address).toBe("u1abc");
      expect(result.amount).toBe("1.5");
    });

    it("decodes base64url memo", () => {
      const result = zns.parseZip321Uri("zcash:u1abc?memo=SGVsbG8");
      expect(result.memoDecoded).toBe("Hello");
    });

    it("returns empty strings for missing fields", () => {
      const result = zns.parseZip321Uri("zcash:u1abc");
      expect(result.amount).toBe("");
      expect(result.memoRaw).toBe("");
      expect(result.memoDecoded).toBe("");
    });

    it("handles zcash: prefix case-insensitively", () => {
      const result = zns.parseZip321Uri("ZCASH:u1abc");
      expect(result.address).toBe("u1abc");
    });
  });

  describe("verifyProof", () => {
    // Independent reimplementation of the leaf/internal hash to build proofs
    // for testing. Must match src/zns.ts byte-for-byte; if these diverge the
    // round-trip test fails immediately, surfacing the drift.
    const LEAF = new TextEncoder().encode("ZNSv1:LEAF\0");
    const NODE = new TextEncoder().encode("ZNSv1:NODE\0");
    const NUL = new Uint8Array([0]);
    const enc = new TextEncoder();
    const u64be = (n: number) => {
      const b = new Uint8Array(8);
      new DataView(b.buffer).setBigUint64(0, BigInt(n), false);
      return b;
    };
    const cat = (...xs: Uint8Array[]) => {
      const out = new Uint8Array(xs.reduce((s, x) => s + x.length, 0));
      let off = 0;
      for (const x of xs) {
        out.set(x, off);
        off += x.length;
      }
      return out;
    };
    const toHex = (b: Uint8Array) =>
      Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

    type Leaf = {
      name: string;
      address: string;
      nonce: number;
      lastAction: LastAction;
    };
    const hashLeaf = (l: Leaf) =>
      blake2b(
        cat(
          LEAF,
          enc.encode(l.name),
          NUL,
          enc.encode(l.address),
          NUL,
          u64be(l.nonce),
          enc.encode(l.lastAction),
          NUL,
        ),
        { dkLen: 32 },
      );
    const hashNode = (a: Uint8Array, b: Uint8Array) =>
      blake2b(cat(NODE, a, b), { dkLen: 32 });

    const merkleRoot = (leaves: Uint8Array[]): Uint8Array => {
      if (leaves.length === 0) return new Uint8Array(32);
      let level = leaves.slice();
      while (level.length > 1) {
        if (level.length % 2 === 1) level.push(level[level.length - 1]);
        const next: Uint8Array[] = [];
        for (let i = 0; i < level.length; i += 2)
          next.push(hashNode(level[i], level[i + 1]));
        level = next;
      }
      return level[0];
    };

    const merklePath = (leaves: Uint8Array[], index: number): Uint8Array[] => {
      let level = leaves.slice();
      let idx = index;
      const path: Uint8Array[] = [];
      while (level.length > 1) {
        if (level.length % 2 === 1) level.push(level[level.length - 1]);
        path.push(idx % 2 === 0 ? level[idx + 1] : level[idx - 1]);
        idx = Math.floor(idx / 2);
        const next: Uint8Array[] = [];
        for (let i = 0; i < level.length; i += 2)
          next.push(hashNode(level[i], level[i + 1]));
        level = next;
      }
      return path;
    };

    const buildRegWithProof = (
      leaves: Leaf[],
      target: number,
    ): RegistrationWithProof => {
      const hashes = leaves.map(hashLeaf);
      const root = merkleRoot(hashes);
      const path = merklePath(hashes, target);
      const proof: MerkleProof = {
        index: target,
        path: path.map(toHex),
        root: toHex(root),
        height: 1000,
        leafCount: leaves.length,
      };
      return {
        ...leaves[target],
        txid: "tx",
        height: 100,
        signature: null,
        listing: null,
        proof,
      } as RegistrationWithProof;
    };

    const sampleLeaves: Leaf[] = [
      { name: "alice",   address: "u1alice",   nonce: 1, lastAction: "CLAIM"  },
      { name: "bob",     address: "u1bob",     nonce: 3, lastAction: "UPDATE" },
      { name: "carol",   address: "u1carol",   nonce: 0, lastAction: "BUY"    },
      { name: "dave",    address: "u1dave",    nonce: 7, lastAction: "CLAIM"  },
      { name: "eve",     address: "u1eve",     nonce: 2, lastAction: "UPDATE" },
    ];

    it("verifies a valid proof for each leaf in a 5-leaf tree", () => {
      for (let i = 0; i < sampleLeaves.length; i++) {
        const reg = buildRegWithProof(sampleLeaves, i);
        expect(zns.verifyProof(reg), `index ${i}`).toBe(true);
      }
    });

    it("verifies a single-leaf tree (empty path)", () => {
      const reg = buildRegWithProof([sampleLeaves[0]], 0);
      expect(reg.proof.path).toEqual([]);
      expect(zns.verifyProof(reg)).toBe(true);
    });

    it("rejects a proof when the address has been tampered with", () => {
      const reg = buildRegWithProof(sampleLeaves, 1);
      reg.address = "u1evil";
      expect(zns.verifyProof(reg)).toBe(false);
    });

    it("rejects a proof when the nonce has been tampered with", () => {
      const reg = buildRegWithProof(sampleLeaves, 2);
      reg.nonce = 999;
      expect(zns.verifyProof(reg)).toBe(false);
    });

    it("rejects a proof when a sibling hash has been swapped", () => {
      const reg = buildRegWithProof(sampleLeaves, 3);
      const tampered = reg.proof.path.slice();
      tampered[0] = "00".repeat(32);
      reg.proof = { ...reg.proof, path: tampered };
      expect(zns.verifyProof(reg)).toBe(false);
    });

    it("rejects a proof against a wrong root", () => {
      const reg = buildRegWithProof(sampleLeaves, 0);
      reg.proof = { ...reg.proof, root: "00".repeat(32) };
      expect(zns.verifyProof(reg)).toBe(false);
    });
  });
});