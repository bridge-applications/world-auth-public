import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NonceService } from "../src/logic/server/helpers/NonceService.js";
import { NOW } from "./fixtures.js";
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW + 123);
});
afterEach(() => vi.useRealTimers());
describe("nonce integrity and expiry", () => {
  it("issues distinct MiniKit-compatible challenges with matching encoded expiry", () => {
    const service = new NonceService("n".repeat(32));
    const challenges = Array.from({ length: 100 }, () => service.genNonce());
    expect(new Set(challenges.map((x) => x.nonce)).size).toBe(100);
    for (const challenge of challenges) {
      expect(challenge.nonce).toMatch(/^[a-zA-Z0-9]{72}$/);
      expect(service.verifyNonce(challenge.nonce)).toEqual({
        valid: true,
        expiresAtMs: challenge.expiresAtMs,
      });
    }
  });
  it("rejects tampering, wrong signing keys, and expiry at the exact boundary", () => {
    const service = new NonceService("n".repeat(32));
    const challenge = service.genNonce();
    const tampered =
      (challenge.nonce[0] === "a" ? "b" : "a") + challenge.nonce.slice(1);
    expect(service.verifyNonce(tampered)).toMatchObject({
      valid: false,
      reason: "invalid_signature",
    });
    expect(
      new NonceService("x".repeat(32)).verifyNonce(challenge.nonce).valid,
    ).toBe(false);
    vi.setSystemTime(challenge.expiresAtMs - 1);
    expect(service.verifyNonce(challenge.nonce).valid).toBe(true);
    vi.setSystemTime(challenge.expiresAtMs);
    expect(service.verifyNonce(challenge.nonce)).toEqual({
      valid: false,
      reason: "expired",
    });
  });
  it.each([
    "",
    "!".repeat(72),
    "g".repeat(72),
    "A".repeat(72),
    "a".repeat(10000),
  ])("rejects malformed nonce %j", (nonce) => {
    expect(new NonceService("n".repeat(32)).verifyNonce(nonce)).toMatchObject({
      valid: false,
      reason: "invalid_format",
    });
  });
  it.each([0, -1, 999, 900001, Infinity, NaN, 1000.5])(
    "rejects invalid TTL %s",
    (ttl) => {
      expect(() => new NonceService("n".repeat(32)).genNonce(ttl)).toThrow(
        "TTL",
      );
    },
  );
  it("validates secret length by bytes", () => {
    expect(() => new NonceService("short")).toThrow("32");
    expect(() => new NonceService("é".repeat(16))).not.toThrow();
  });
});
