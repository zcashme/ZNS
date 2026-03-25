import { describe, it, expect } from "vitest";
import { isValidName } from "../src/validation.js";

describe("isValidName", () => {
  it("accepts lowercase alphanumeric", () => {
    expect(isValidName("alice")).toBe(true);
    expect(isValidName("bob123")).toBe(true);
    expect(isValidName("a")).toBe(true);
    expect(isValidName("0")).toBe(true);
  });

  it("accepts hyphens in the middle", () => {
    expect(isValidName("my-name")).toBe(true);
    expect(isValidName("a-b-c")).toBe(true);
  });

  it("accepts max length (62 chars)", () => {
    expect(isValidName("a".repeat(62))).toBe(true);
  });

  it("rejects empty string", () => {
    expect(isValidName("")).toBe(false);
  });

  it("rejects over 62 chars", () => {
    expect(isValidName("a".repeat(63))).toBe(false);
  });

  it("rejects uppercase", () => {
    expect(isValidName("Alice")).toBe(false);
    expect(isValidName("BOB")).toBe(false);
  });

  it("rejects special characters", () => {
    expect(isValidName("alice!")).toBe(false);
    expect(isValidName("bob@123")).toBe(false);
    expect(isValidName("my_name")).toBe(false);
    expect(isValidName("my.name")).toBe(false);
  });

  it("rejects leading hyphen", () => {
    expect(isValidName("-alice")).toBe(false);
  });

  it("rejects trailing hyphen", () => {
    expect(isValidName("alice-")).toBe(false);
  });

  it("rejects consecutive hyphens", () => {
    expect(isValidName("al--ice")).toBe(false);
  });
});
