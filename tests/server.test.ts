import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { WorldAuthServer } from "../src/server.js";
import type { WorldAuthServerConfig } from "../src/server.js";
import { config, memoryNonces, NOW, wallet } from "./fixtures.js";
const mocks = vi.hoisted(() => ({
  verify: vi.fn(),
  parse: vi.fn(),
  get: vi.fn(),
  incr: vi.fn(),
  set: vi.fn(),
}));
vi.mock("viem/actions", () => ({ verifyMessage: mocks.verify }));
vi.mock("viem/siwe", async (importOriginal) => {
  const actual = await importOriginal<typeof import("viem/siwe")>();
  return { ...actual, parseSiweMessage: mocks.parse };
});
vi.mock("@upstash/redis", () => ({
  Redis: class {
    get = mocks.get;
    incr = mocks.incr;
    set = mocks.set;
  },
}));
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
  vi.clearAllMocks();
});
afterEach(() => vi.useRealTimers());

describe("application configuration", () => {
  it("reuses the same config object even during concurrent initialization", async () => {
    const options = config();
    const [first, second] = await Promise.all([
      WorldAuthServer.init(options),
      WorldAuthServer.init(options),
    ]);
    expect(first).toBe(second);
    expect(await WorldAuthServer.create(options)).not.toBe(first);
  });
  it("isolates schemas with identical field names", async () => {
    const first = await WorldAuthServer.init({
      ...config(),
      accessTokenConfig: {
        ttlMs: 1000,
        payloadSchema: z.object({ value: z.string() }),
      },
    });
    const second = await WorldAuthServer.init({
      ...config(),
      accessTokenConfig: {
        ttlMs: 1000,
        payloadSchema: z.object({ value: z.number() }),
      },
    });
    expect(first).not.toBe(second);
    await expect(
      first.genAccessToken({ value: "text" }),
    ).resolves.toBeDefined();
    await expect(second.genAccessToken({ value: "text" })).rejects.toThrow();
  });
  it("captures key bytes and token configuration instead of mutable references", async () => {
    const options = {
      ...config(),
      secrets: { ...config().secrets, jweSecret: new Uint8Array(32).fill(7) },
    };
    const auth = await WorldAuthServer.create(options);
    options.secrets.jweSecret.fill(0);
    options.accessTokenConfig.ttlMs = 1;
    const token = await auth.genAccessToken({ userId: "u" });
    expect(token.accessTokenExpiresAt).toBe(NOW + 60_000);
    await expect(
      auth.verifyAccessToken(token.accessToken),
    ).resolves.toBeDefined();
  });
  it.each([0, -1, NaN, Infinity, 1000.1])(
    "rejects invalid token TTL %s",
    async (ttlMs) => {
      await expect(
        WorldAuthServer.create({ ...config(), accessTokenConfig: { ttlMs } }),
      ).rejects.toThrow("TTL");
    },
  );
  it.each(["short", "é".repeat(32)])(
    "requires exactly 32 key bytes",
    async (jweSecret) => {
      await expect(
        WorldAuthServer.create({
          ...config(),
          secrets: { ...config().secrets, jweSecret },
        }),
      ).rejects.toThrow("32");
    },
  );
  it("rejects invalid namespaces, missing identity fields, and absent revocation stores", async () => {
    await expect(
      WorldAuthServer.create({ ...config(), namespace: "a:b" }),
    ).rejects.toThrow("namespace");
    await expect(
      WorldAuthServer.create({
        ...config(),
        refreshTokenConfig: { ...config().refreshTokenConfig, idField: "" },
      }),
    ).rejects.toThrow("idField");
    await expect(
      WorldAuthServer.create({ ...config(), tokenGroupStore: undefined }),
    ).rejects.toThrow("Configure Redis");
  });
  it("rejects non-schema config passed from JavaScript", async () => {
    const options: WorldAuthServerConfig = config();
    Reflect.set(options.refreshTokenConfig, "payloadSchema", {});
    await expect(WorldAuthServer.create(options)).rejects.toThrow("Zod schema");
    const access: WorldAuthServerConfig = config();
    Reflect.set(access.accessTokenConfig, "payloadSchema", {});
    await expect(WorldAuthServer.create(access)).rejects.toThrow("Zod schema");
  });
});

describe("wallet proof and challenge consumption", () => {
  const proof = {
    status: "success",
    version: 1,
    address: wallet,
    signature: "0x" + "ab".repeat(65),
    message: "signed message",
  };
  async function setup() {
    const options = config();
    const auth = await WorldAuthServer.create(options);
    const { nonce } = await auth.genNonce();
    const context = {
      expectedNonce: nonce,
      domain: "app.example",
      uri: "https://app.example",
    };
    mocks.verify.mockResolvedValue(true);
    mocks.parse.mockReturnValue({
      version: "1",
      issuedAt: new Date(NOW),
      statement: "Sign in",
      requestId: "request-1",
      address: wallet,
      domain: context.domain,
      uri: context.uri,
      chainId: 480,
      nonce,
    });
    return { auth, nonce, context, store: options.nonceStore };
  }
  it("accepts a valid session-bound wallet proof once", async () => {
    const { auth, nonce, context, store } = await setup();
    expect(
      await auth.verifySiwe(proof, nonce, {
        ...context,
        statement: "Sign in",
        requestId: "request-1",
      }),
    ).toBe(true);
    expect(mocks.verify).toHaveBeenCalledWith(expect.anything(), {
      address: proof.address,
      message: proof.message,
      signature: proof.signature,
      mode: "eoa",
    });
    expect(await auth.verifySiwe(proof, nonce, context)).toBe(false);
    expect(store.consume).toHaveBeenCalledTimes(2);
  });
  it("allows exactly one winner under simultaneous replay", async () => {
    const { auth, nonce, context } = await setup();
    expect(
      (
        await Promise.all(
          Array.from({ length: 10 }, () =>
            auth.verifySiwe(proof, nonce, context),
          ),
        )
      ).filter(Boolean),
    ).toHaveLength(1);
  });
  it("rejects a challenge from a different browser session before signature verification", async () => {
    const { auth, nonce, context, store } = await setup();
    expect(
      await auth.verifySiwe(proof, nonce, {
        ...context,
        expectedNonce: "other",
      }),
    ).toBe(false);
    expect(mocks.verify).not.toHaveBeenCalled();
    expect(store.consume).not.toHaveBeenCalled();
  });
  it.each([
    { domain: "evil.example" },
    { uri: "https://evil.example" },
    { chainId: 1 },
    { address: "0x" + "a".repeat(40) },
    { nonce: "another-nonce" },
  ])("rejects a signed message with the wrong context %j", async (change) => {
    const { auth, nonce, context, store } = await setup();
    mocks.verify.mockResolvedValue(true);
    mocks.parse.mockReturnValue({
      version: "1",
      issuedAt: new Date(NOW),
      statement: "Sign in",
      requestId: "request-1",
      address: wallet,
      domain: context.domain,
      uri: context.uri,
      chainId: 480,
      nonce,
      ...change,
    });
    expect(await auth.verifySiwe(proof, nonce, context)).toBe(false);
    expect(store.consume).not.toHaveBeenCalled();
  });
  it("does not consume invalid proofs and fails closed on verifier or store errors", async () => {
    const { auth, nonce, context, store } = await setup();
    mocks.verify.mockResolvedValueOnce(false);
    expect(await auth.verifySiwe(proof, nonce, context)).toBe(false);
    expect(store.consume).not.toHaveBeenCalled();
    mocks.verify.mockRejectedValueOnce(new Error("RPC failed"));
    expect(await auth.verifySiwe(proof, nonce, context)).toBe(false);
    store.consume.mockRejectedValueOnce(new Error("store unavailable"));
    expect(await auth.verifySiwe(proof, nonce, context)).toBe(false);
  });
  it("rejects malformed, expired, or absent challenge context", async () => {
    const { auth, nonce, context } = await setup();
    expect(await auth.verifySiwe({}, nonce, context)).toBe(false);
    expect(
      await auth.verifySiwe(proof, nonce, { ...context, domain: "" }),
    ).toBe(false);
    const noStore = await WorldAuthServer.create({
      ...config(),
      nonceStore: undefined,
    });
    expect(await noStore.verifySiwe(proof, nonce, context)).toBe(false);
    vi.setSystemTime(NOW + 300_000);
    expect(await auth.verifySiwe(proof, nonce, context)).toBe(false);
  });
  it("rechecks nonce expiry after the verifier finishes", async () => {
    const { auth, nonce, context, store } = await setup();
    mocks.verify.mockImplementationOnce(async () => {
      vi.setSystemTime(NOW + 300_000);
      return true;
    });
    expect(await auth.verifySiwe(proof, nonce, context)).toBe(false);
    expect(store.consume).not.toHaveBeenCalled();
  });
  it("uses Redis NX and a bounded TTL for atomic challenge consumption", async () => {
    const options = {
      ...config(),
      nonceStore: undefined,
      tokenGroupStore: undefined,
      redisConfig: {
        redisUrl: "https://redis.example",
        redisToken: "test-credential",
      },
    };
    mocks.get.mockResolvedValue(null);
    mocks.set.mockResolvedValue("OK");
    const auth = await WorldAuthServer.create(options);
    const { nonce, expiresAtMs } = await auth.genNonce();
    const context = {
      expectedNonce: nonce,
      domain: "app.example",
      uri: "https://app.example",
    };
    mocks.verify.mockResolvedValue(true);
    mocks.parse.mockReturnValue({
      version: "1",
      issuedAt: new Date(NOW),
      statement: "Sign in",
      requestId: "request-1",
      address: wallet,
      domain: context.domain,
      uri: context.uri,
      chainId: 480,
      nonce,
    });
    expect(await auth.verifySiwe(proof, nonce, context)).toBe(true);
    expect(mocks.set).toHaveBeenCalledWith(
      expect.stringMatching(/^test-app:nonce:[a-f0-9]{64}$/),
      "used",
      { nx: true, px: expiresAtMs - NOW },
    );
    mocks.set.mockResolvedValue(null);
    expect(await auth.verifySiwe(proof, nonce, context)).toBe(false);
    await expect(auth.genRefreshToken({ userId: "u" })).resolves.toBeDefined();
  });
});

describe("cookie adapters and safe diagnostics", () => {
  it("sets secure host-scoped cookies with maxAge in seconds and clamps expired cookies", async () => {
    const auth = await WorldAuthServer.create(config());
    const write = vi.fn();
    await auth.setRefreshTokenCookie("credential", NOW + 10_500, write);
    expect(write).toHaveBeenLastCalledWith({
      name: "worldAuth_refreshToken",
      value: "credential",
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      path: "/",
      maxAge: 10,
    });
    await auth.setRefreshTokenCookie("credential", NOW - 1, write);
    expect(write.mock.lastCall?.[0].maxAge).toBe(0);
    const clear = vi.fn();
    await auth.clearRefreshTokenCookie(clear);
    expect(clear).toHaveBeenCalledWith("worldAuth_refreshToken", {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      path: "/",
      maxAge: 0,
    });
    expect(auth.getRefreshTokenCookie(() => "credential")).toBe("credential");
    expect(auth.getRefreshTokenCookie(() => "")).toBeNull();
    await expect(
      auth.setRefreshTokenCookie("credential", NaN, write),
    ).rejects.toThrow("expiry");
  });
  it("never prints credentials or wallet payloads with debug enabled", async () => {
    const logs = vi.spyOn(console, "debug").mockImplementation(() => {});
    const options = { ...config(), debug: true, nonceStore: memoryNonces() };
    const auth = await WorldAuthServer.create(options);
    const { nonce } = await auth.genNonce();
    mocks.verify.mockRejectedValueOnce(new Error("secret-signed-payload"));
    await auth.verifySiwe(
      {
        status: "success",
        version: 1,
        address: wallet,
        signature: "private-proof",
        message: "secret-message",
      },
      nonce,
      {
        expectedNonce: nonce,
        domain: "app.example",
        uri: "https://app.example",
      },
    );
    await auth.genAccessToken({ userId: "sensitive-user" });
    const output = JSON.stringify(logs.mock.calls);
    for (const value of [
      "private-proof",
      "secret-message",
      "sensitive-user",
      options.secrets.jweSecret,
      options.secrets.nonceSecret,
    ])
      expect(output).not.toContain(value);
  });
});
