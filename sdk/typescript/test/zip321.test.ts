import { describe, it, expect } from "vitest";
import {
  toBase64Url,
  decodeBase64Url,
  buildZcashUri,
  parseZip321Uri,
} from "../src/zip321.js";

describe("toBase64Url / decodeBase64Url", () => {
  it("round-trips plain text", () => {
    const text = "ZNS:CLAIM:alice:u1testaddr";
    expect(decodeBase64Url(toBase64Url(text))).toBe(text);
  });

  it("round-trips unicode", () => {
    const text = "hello world 🎉";
    expect(decodeBase64Url(toBase64Url(text))).toBe(text);
  });

  it("produces URL-safe characters", () => {
    const encoded = toBase64Url("test+/data==");
    expect(encoded).not.toMatch(/[+/=]/);
  });
});

describe("buildZcashUri", () => {
  it("builds address-only URI", () => {
    expect(buildZcashUri("u1addr")).toBe("zcash:u1addr");
  });

  it("builds URI with amount", () => {
    expect(buildZcashUri("u1addr", "0.25")).toBe("zcash:u1addr?amount=0.25");
  });

  it("builds URI with amount and memo", () => {
    const uri = buildZcashUri("u1addr", "1.5", "ZNS:CLAIM:alice:u1buyer");
    expect(uri).toMatch(/^zcash:u1addr\?amount=1\.5&memo=/);
  });

  it("accepts numeric amount", () => {
    expect(buildZcashUri("u1addr", 0.75)).toBe("zcash:u1addr?amount=0.75");
  });

  it("skips zero amount", () => {
    expect(buildZcashUri("u1addr", 0)).toBe("zcash:u1addr");
  });

  it("returns empty for empty address", () => {
    expect(buildZcashUri("")).toBe("");
  });
});

describe("parseZip321Uri", () => {
  it("parses a full URI", () => {
    const memo = "ZNS:CLAIM:alice:u1buyer";
    const uri = buildZcashUri("u1addr", "1.5", memo);
    const parts = parseZip321Uri(uri);
    expect(parts.address).toBe("u1addr");
    expect(parts.amount).toBe("1.5");
    expect(parts.memoDecoded).toBe(memo);
  });

  it("parses address-only URI", () => {
    const parts = parseZip321Uri("zcash:u1addr");
    expect(parts.address).toBe("u1addr");
    expect(parts.amount).toBe("");
    expect(parts.memoDecoded).toBe("");
  });
});
