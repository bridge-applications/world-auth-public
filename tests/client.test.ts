import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import {
  WorldAuthClient,
  ApiAuthCompleteSiweReqSchema,
  ApiAuthCompleteSiweResSchema,
  ApiStatus,
  ApiResCodes,
  HttpStatusCodes,
} from "../src/client.js";
import type {
  WorldAuthClientConfigInput,
  TokenStorage,
} from "../src/client.js";
import { callBackend } from "../src/logic/client/helpers/callBackend.js";
import { NOW, wallet, deferred } from "./fixtures.js";
const base = {
  status: ApiStatus.SUCCESS,
  statusCode: HttpStatusCodes.OK,
  respCode: ApiResCodes.SUCCESS_REQUEST_COMPLETED,
  version: "test",
};
const access = {
  ...base,
  accessToken: "access-credential",
  accessTokenExpiresAt: NOW + 60_000,
};
const auth = {
  ...access,
  refreshTokenExpiresAt: NOW + 3_600_000,
  walletAddress: wallet,
  userId: "user-1",
};
const proof = {
  nonce: "testnonce123",
  payload: {
    status: "success" as const,
    version: 1,
    address: wallet,
    signature: "signed-proof",
    message: "signed-message",
  },
};
function response(value: unknown, status = 200) {
  return Response.json(value, { status });
}
function storage() {
  const values = new Map<string, string>();
  return {
    values,
    getItem: vi.fn((key: string) => values.get(key) ?? null),
    setItem: vi.fn((key: string, value: string) => {
      values.set(key, value);
    }),
    removeItem: vi.fn((key: string) => {
      values.delete(key);
    }),
  } satisfies TokenStorage & { values: Map<string, string> };
}
function init(extra: Partial<WorldAuthClientConfigInput> = {}) {
  const miniKit = {
    walletAuth: vi.fn(async () => ({
      executedWith: "minikit",
      data: proof.payload,
    })),
  };
  WorldAuthClient.init({ baseUrl: "https://app.example", miniKit, ...extra });
  return miniKit;
}
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
  WorldAuthClient.reset();
});
afterEach(() => {
  WorldAuthClient.reset();
  vi.useRealTimers();
});

describe("client token lifecycle", () => {
  it("keeps access credentials in memory by default", async () => {
    init();
    const fetch = vi.fn().mockResolvedValue(response(access));
    vi.stubGlobal("fetch", fetch);
    await WorldAuthClient.getAccessToken();
    expect(WorldAuthClient.isAuthenticated).toBe(true);
    expect(await WorldAuthClient.getAccessTokenSilently()).toEqual({
      accessToken: access.accessToken,
      accessTokenExpiresAt: access.accessTokenExpiresAt,
    });
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("deduplicates simultaneous refreshes and clears the flight after failure", async () => {
    init();
    const pending = deferred<Response>();
    const fetch = vi
      .fn()
      .mockReturnValueOnce(pending.promise)
      .mockResolvedValueOnce(response(access));
    vi.stubGlobal("fetch", fetch);
    const calls = Array.from({ length: 10 }, () =>
      WorldAuthClient.getAccessTokenSilently(),
    );
    expect(fetch).toHaveBeenCalledTimes(1);
    pending.resolve(response(access));
    await Promise.all(calls);
    vi.setSystemTime(NOW + 60_000);
    fetch.mockRejectedValueOnce(new Error("offline"));
    // Direct requests still share a flight; the next failed attempt must not poison it.
    await WorldAuthClient.getAccessToken();
    await expect(WorldAuthClient.getAccessToken()).rejects.toMatchObject({
      code: "NETWORK_ERROR",
    });
    fetch.mockResolvedValueOnce(
      response({ ...access, accessTokenExpiresAt: NOW + 120_000 }),
    );
    await expect(WorldAuthClient.getAccessToken()).resolves.toBeDefined();
  });
  it("refreshes at the exact cached expiry boundary", async () => {
    init();
    WorldAuthClient.commitAccess(access);
    vi.setSystemTime(access.accessTokenExpiresAt);
    const fetch = vi
      .fn()
      .mockResolvedValue(
        response({ ...access, accessTokenExpiresAt: NOW + 120_000 }),
      );
    vi.stubGlobal("fetch", fetch);
    expect(WorldAuthClient.isAuthenticated).toBe(false);
    await WorldAuthClient.getAccessTokenSilently();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("stores and restores validated token fields under an application-specific key", () => {
    const cache = storage();
    init({ storage: cache, storageKey: "app.tokens" });
    WorldAuthClient.commitAuth(auth);
    expect(cache.values.has("app.tokens")).toBe(true);
    WorldAuthClient.reset();
    init({ storage: cache, storageKey: "app.tokens" });
    expect(WorldAuthClient.isAuthenticated).toBe(true);
    expect(WorldAuthClient.expectedToBeAuthenticated).toBe(true);
    vi.setSystemTime(auth.refreshTokenExpiresAt);
    WorldAuthClient.reset();
    init({ storage: cache, storageKey: "app.tokens" });
    expect(WorldAuthClient.isAuthenticated).toBe(false);
    expect(WorldAuthClient.expectedToBeAuthenticated).toBe(false);
  });
  it.each([
    "not-json",
    JSON.stringify({ accessToken: 42 }),
    JSON.stringify({ accessToken: "token", accessTokenExpiresAt: NOW - 1 }),
  ])("clears corrupt or expired cached credentials", (raw) => {
    const cache = storage();
    cache.values.set("worldAuth.tokens", raw);
    init({ storage: cache });
    expect(WorldAuthClient.isAuthenticated).toBe(false);
    expect(
      JSON.parse(cache.values.get("worldAuth.tokens") ?? "{}").accessToken,
    ).toBeUndefined();
  });
  it("continues in memory when browser storage is blocked", async () => {
    const cache: TokenStorage = {
      getItem: () => {
        throw new Error("denied");
      },
      setItem: () => {
        throw new Error("denied");
      },
      removeItem: () => {
        throw new Error("denied");
      },
    };
    init({ storage: cache });
    WorldAuthClient.commitAuth(auth);
    expect(WorldAuthClient.isAuthenticated).toBe(true);
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    await expect(WorldAuthClient.signOut()).rejects.toThrow();
    expect(WorldAuthClient.isAuthenticated).toBe(false);
  });
  it("clears memory and persistent storage even when sign-out fails", async () => {
    const cache = storage();
    init({ storage: cache });
    WorldAuthClient.commitAuth(auth);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response({}, 500)));
    await expect(WorldAuthClient.signOut()).rejects.toMatchObject({
      code: "HTTP_ERROR",
    });
    expect(WorldAuthClient.isAuthenticated).toBe(false);
    expect(cache.values.has("worldAuth.tokens")).toBe(false);
  });
  it.each(["logout", "reset", "reinitialize"])(
    "rejects late refresh responses after %s",
    async (operation) => {
      const cache = storage();
      init({ storage: cache });
      const pending = deferred<Response>();
      vi.stubGlobal(
        "fetch",
        vi
          .fn()
          .mockReturnValueOnce(pending.promise)
          .mockResolvedValue(response({ ...base, success: true })),
      );
      const stale = expect(WorldAuthClient.getAccessToken()).rejects.toThrow(
        "superseded",
      );
      if (operation === "logout") await WorldAuthClient.signOut();
      if (operation === "reset") {
        WorldAuthClient.reset();
        init({ storage: cache });
      }
      if (operation === "reinitialize") init({ storage: cache });
      pending.resolve(response(access));
      await stale;
      expect(WorldAuthClient.isAuthenticated).toBe(false);
      expect(cache.values.has("worldAuth.tokens")).toBe(false);
    },
  );
  it("clears cached credentials when clearing cookies", async () => {
    init();
    WorldAuthClient.commitAuth(auth);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(response({ ...base, success: true })),
    );
    await WorldAuthClient.clearCookies();
    expect(WorldAuthClient.isAuthenticated).toBe(false);
  });
  it("honors deferred authentication commits", async () => {
    init();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response(auth)));
    const result = await WorldAuthClient.completeSiwe(
      proof,
      undefined,
      undefined,
      {},
      { deferCommit: true },
    );
    expect(WorldAuthClient.isAuthenticated).toBe(false);
    WorldAuthClient.commitAuth(result);
    expect(WorldAuthClient.isAuthenticated).toBe(true);
  });
  it("uses schema overrides for privileged application session flows", async () => {
    const req = z.object({ userId: z.string(), extra: z.string() });
    const res = ApiAuthCompleteSiweResSchema.extend({ team: z.string() });
    init({
      customSchemas: { appSession: { req, res } },
      urlPaths: { appSession: "/custom-session" },
    });
    const fetch = vi
      .fn()
      .mockResolvedValue(response({ ...auth, team: "engineering" }));
    vi.stubGlobal("fetch", fetch);
    const result = await WorldAuthClient.getAppSession(
      { userId: "u", extra: "value" },
      req,
      res,
      { "x-application-auth": "private-credential" },
    );
    expect(result.team).toBe("engineering");
    expect(WorldAuthClient.isAuthenticated).toBe(true);
    expect(fetch.mock.calls[0]?.[0]).toBe("https://app.example/custom-session");
  });
});

it("blocks new authentication while logout requests are still pending", async () => {
  init();
  WorldAuthClient.commitAuth(auth);
  const pending = deferred<Response>();
  const fetch = vi
    .fn()
    .mockReturnValueOnce(pending.promise)
    .mockResolvedValueOnce(response(access));
  vi.stubGlobal("fetch", fetch);
  const logout = WorldAuthClient.signOut();
  await expect(WorldAuthClient.getAccessTokenSilently()).rejects.toThrow(
    "sign-out is in progress",
  );
  await expect(WorldAuthClient.completeSiwe(proof)).rejects.toThrow(
    "sign-out is in progress",
  );
  expect(() => WorldAuthClient.commitAuth(auth)).toThrow(
    "sign-out is in progress",
  );
  expect(fetch).toHaveBeenCalledTimes(1);
  pending.resolve(response({ ...base, success: true }));
  await logout;
  expect(WorldAuthClient.isAuthenticated).toBe(false);
  await expect(WorldAuthClient.getAccessToken()).resolves.toBeDefined();
});

describe("MiniKit v2 wallet commands", () => {
  it.each(["minikit", "wagmi"])(
    "completes the %s wallet flow with a backend challenge",
    async (executedWith) => {
      const miniKit = init();
      miniKit.walletAuth.mockResolvedValue({
        executedWith,
        data: proof.payload,
      });
      const fetch = vi
        .fn()
        .mockResolvedValueOnce(
          response({
            ...base,
            nonce: proof.nonce,
            nonceExpiresAt: NOW + 300_000,
          }),
        )
        .mockResolvedValueOnce(response(auth));
      vi.stubGlobal("fetch", fetch);
      expect(
        await WorldAuthClient.walletAuth({
          statement: "Sign in",
          requestId: "r1",
        }),
      ).toEqual(auth);
      expect(miniKit.walletAuth).toHaveBeenCalledWith(
        expect.objectContaining({
          nonce: proof.nonce,
          statement: "Sign in",
          requestId: "r1",
          expirationTime: new Date(NOW + 300_000),
        }),
      );
      expect(WorldAuthClient.isAuthenticated).toBe(true);
      expect(WorldAuthClient.expectedToBeAuthenticated).toBe(true);
    },
  );
  it.each([
    { executedWith: "fallback", data: proof.payload },
    { executedWith: "minikit", data: {} },
    null,
  ])("rejects unsuccessful wallet results %j", async (result) => {
    init({ miniKit: { walletAuth: vi.fn().mockResolvedValue(result) } });
    const fetch = vi.fn().mockResolvedValue(
      response({
        ...base,
        nonce: proof.nonce,
        nonceExpiresAt: NOW + 300_000,
      }),
    );
    vi.stubGlobal("fetch", fetch);
    await expect(WorldAuthClient.walletAuth()).rejects.toThrow(
      "successful proof",
    );
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("does not commit a wallet result after logout during the native command", async () => {
    const command = deferred<unknown>();
    init({ miniKit: { walletAuth: () => command.promise } });
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          response({
            ...base,
            nonce: proof.nonce,
            nonceExpiresAt: NOW + 300_000,
          }),
        )
        .mockResolvedValue(response({ ...base, success: true })),
    );
    const signing = WorldAuthClient.walletAuth();
    const rejected = expect(signing).rejects.toThrow("superseded");
    await vi.waitFor(() => expect(WorldAuthClient.isInitialized()).toBe(true));
    await WorldAuthClient.signOut();
    command.resolve({ executedWith: "minikit", data: proof.payload });
    await rejected;
    expect(WorldAuthClient.isAuthenticated).toBe(false);
  });
});

describe("HTTP validation and diagnostics", () => {
  const schema = {
    req: ApiAuthCompleteSiweReqSchema,
    res: ApiAuthCompleteSiweResSchema,
  };
  it("validates requests before sending them and sends cookies with JSON requests", async () => {
    const fetch = vi.fn().mockResolvedValue(response(auth));
    vi.stubGlobal("fetch", fetch);
    await expect(
      callBackend("https://app.example", "/auth", "POST", schema, {}),
    ).rejects.toMatchObject({ code: "REQUEST_VALIDATION" });
    expect(fetch).not.toHaveBeenCalled();
    await callBackend("https://app.example", "/auth", "POST", schema, proof);
    expect(fetch.mock.calls[0]?.[1]).toMatchObject({
      method: "POST",
      credentials: "include",
    });
    expect(JSON.parse(fetch.mock.calls[0]?.[1].body)).toEqual(proof);
  });
  it.each([
    { ...base, status: ApiStatus.ERROR },
    { ...base, statusCode: HttpStatusCodes.UNAUTHORIZED },
  ])("rejects API errors even when HTTP status is 200", async (body) => {
    init();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response(body)));
    await expect(WorldAuthClient.getAccessToken()).rejects.toMatchObject({
      code: "API_ERROR",
    });
    expect(WorldAuthClient.isAuthenticated).toBe(false);
  });
  it.each([{}, { ...auth, accessTokenExpiresAt: "tomorrow" }])(
    "rejects malformed response %j",
    async (body) => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response(body)));
      await expect(
        callBackend("https://app.example", "/auth", "POST", schema, proof),
      ).rejects.toMatchObject({ code: "RESPONSE_VALIDATION" });
    },
  );
  it("handles non-JSON responses and HTTP errors without exposing response content", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(new Response("private-data"))
        .mockResolvedValueOnce(new Response("private-data", { status: 401 })),
    );
    await expect(
      callBackend("https://app.example", "/auth", "POST", schema, proof),
    ).rejects.toMatchObject({ code: "RESPONSE_VALIDATION" });
    await expect(
      callBackend("https://app.example", "/auth", "POST", schema, proof),
    ).rejects.toMatchObject({ code: "HTTP_ERROR", status: 401 });
  });
  it("bounds stalled network requests and reports timeout distinctly", async () => {
    vi.useFakeTimers();
    vi.stubGlobal(
      "fetch",
      vi.fn(
        (_url: string, options: RequestInit) =>
          new Promise((_resolve, reject) =>
            options.signal?.addEventListener("abort", () =>
              reject(new DOMException("Aborted", "AbortError")),
            ),
          ),
      ),
    );
    const rejected = expect(
      callBackend(
        "https://app.example",
        "/auth",
        "POST",
        schema,
        proof,
        {},
        false,
        100,
      ),
    ).rejects.toMatchObject({ code: "TIMEOUT" });
    await vi.advanceTimersByTimeAsync(100);
    await rejected;
  });
  it("prints only safe metadata with debug enabled", async () => {
    const logs = vi.spyOn(console, "debug").mockImplementation(() => {});
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response(auth)));
    await callBackend(
      "https://app.example",
      "/auth",
      "POST",
      schema,
      proof,
      { Authorization: "Bearer private-header" },
      true,
    );
    expect(JSON.stringify(logs.mock.calls)).not.toMatch(
      /access-credential|private-header|signed-proof|signed-message/,
    );
  });
  it("requires initialization and validates integration configuration", () => {
    expect(WorldAuthClient.isInitialized()).toBe(false);
    expect(() => WorldAuthClient.isAuthenticated).toThrow("not initialized");
    for (const baseUrl of [
      "ftp://app.example",
      "https://user:password@app.example",
      "https://app.example?secret=x",
    ])
      expect(() => init({ baseUrl })).toThrow("baseUrl");
    expect(() => init({ requestTimeoutMs: 0 })).toThrow("requestTimeoutMs");
    expect(() => init({ urlPaths: { nonce: "invalid" } })).toThrow("paths");
    expect(() =>
      init({ miniKit: {} as WorldAuthClientConfigInput["miniKit"] }),
    ).toThrow("walletAuth");
  });
});
