import { beforeEach, afterEach, expect, it, vi } from "vitest";
import { z } from "zod";
import { WorldAuthServer } from "../src/server.js";
import { createAuthHandler } from "../examples/fetch-handler.js";
import { config, NOW, wallet } from "./fixtures.js";
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
});
afterEach(() => vi.useRealTimers());
const origin = "https://app.example";
function request(
  path: string,
  body: unknown,
  cookies = "",
  requestOrigin = origin,
) {
  return new Request(origin + path, {
    method: "POST",
    headers: {
      Origin: requestOrigin,
      "Content-Type": "application/json",
      Cookie: cookies,
    },
    body: JSON.stringify(body),
  });
}
async function setup() {
  const claims = z.object({ userId: z.string(), walletAddress: z.string() });
  const options = config();
  const auth = await WorldAuthServer.create({
    ...options,
    accessTokenConfig: { ttlMs: 60_000, payloadSchema: claims },
    refreshTokenConfig: {
      ttlMs: 3_600_000,
      payloadSchema: claims,
      idField: "userId",
    },
  });
  const verify = vi
    .spyOn(auth, "verifySiwe")
    .mockImplementation(
      async (_payload, nonce, context) => nonce === context.expectedNonce,
    );
  const handle = createAuthHandler(auth, origin);
  const response = await handle(new Request(origin + "/api/auth/nonce"));
  const challenge = (await response.json()) as { nonce: string };
  const challengeCookie = response.headers.getSetCookie()[0]!.split(";")[0]!;
  const proof = {
    nonce: challenge.nonce,
    payload: {
      status: "success",
      version: 1,
      address: wallet,
      message: "signed-message",
      signature: "signed-proof",
    },
  };
  return { auth, options, handle, proof, verify, challengeCookie };
}

it("integrates challenge cookies, token issuance, refresh, and user-wide logout", async () => {
  const { auth, handle, proof, verify, challengeCookie } = await setup();
  const login = await handle(
    request("/api/auth/complete-siwe", proof, challengeCookie),
  );
  expect(login.status).toBe(200);
  expect(login.headers.get("cache-control")).toBe("no-store");
  expect(verify).toHaveBeenCalledWith(proof.payload, proof.nonce, {
    expectedNonce: proof.nonce,
    domain: "app.example",
    uri: origin,
  });
  const body = (await login.json()) as {
    accessToken: string;
    refreshToken?: string;
  };
  expect(body.refreshToken).toBeUndefined();
  expect(
    (await auth.verifyAccessToken(body.accessToken)).payload?.walletAddress,
  ).toBe(wallet);
  const refreshCookie = login.headers
    .getSetCookie()
    .find((value) => value.startsWith("worldAuth_refreshToken="))!;
  expect(refreshCookie).toMatch(/HttpOnly; Secure; SameSite=Strict/);
  const cookiePair = refreshCookie.split(";")[0]!;
  expect(
    (await handle(request("/api/auth/access-token", {}, cookiePair))).status,
  ).toBe(200);
  const logout = await handle(
    request("/api/auth/sign-out", { signAllOut: true }, cookiePair),
  );
  expect(logout.status).toBe(200);
  expect(logout.headers.getSetCookie()[0]).toContain("Max-Age=0");
  expect(
    (await handle(request("/api/auth/access-token", {}, cookiePair))).status,
  ).toBe(401);
});
it("rejects cross-origin login, absent or ambiguous challenge cookies, and a substituted nonce", async () => {
  const { handle, proof, challengeCookie } = await setup();
  expect(
    (
      await handle(
        request(
          "/api/auth/complete-siwe",
          proof,
          challengeCookie,
          "https://evil.example",
        ),
      )
    ).status,
  ).toBe(403);
  expect((await handle(request("/api/auth/complete-siwe", proof))).status).toBe(
    400,
  );
  expect(
    (
      await handle(
        request(
          "/api/auth/complete-siwe",
          proof,
          `${challengeCookie}; ${challengeCookie}`,
        ),
      )
    ).status,
  ).toBe(400);
  expect(
    (
      await handle(
        request(
          "/api/auth/complete-siwe",
          { ...proof, nonce: "differentnonce123" },
          challengeCookie,
        ),
      )
    ).status,
  ).toBe(401);
});
it("rejects oversized, malformed, or non-JSON completion requests", async () => {
  const { handle, challengeCookie } = await setup();
  expect(
    (
      await handle(
        request(
          "/api/auth/complete-siwe",
          { data: "x".repeat(16384) },
          challengeCookie,
        ),
      )
    ).status,
  ).toBe(400);
  expect(
    (
      await handle(
        new Request(origin + "/api/auth/complete-siwe", {
          method: "POST",
          headers: { Origin: origin, "Content-Type": "application/json" },
          body: "invalid-json",
        }),
      )
    ).status,
  ).toBe(400);
  expect(
    (
      await handle(
        new Request(origin + "/api/auth/complete-siwe", {
          method: "POST",
          headers: { Origin: origin },
          body: "data",
        }),
      )
    ).status,
  ).toBe(400);
});
it("rejects missing refresh credentials and clears cookies without claiming revocation", async () => {
  const { handle } = await setup();
  expect((await handle(request("/api/auth/access-token", {}))).status).toBe(
    401,
  );
  expect(
    (await handle(request("/api/auth/sign-out", { signAllOut: "yes" }))).status,
  ).toBe(400);
  const clear = await handle(request("/api/auth/clear-cookies", {}));
  expect(clear.status).toBe(200);
  expect(clear.headers.getSetCookie()).toHaveLength(2);
  expect((await handle(new Request(origin + "/unknown"))).status).toBe(404);
});
it("returns a server error when shared state is unavailable and does not issue credentials", async () => {
  const { options, handle, proof, challengeCookie } = await setup();
  options.tokenGroupStore.get.mockRejectedValue(new Error("unavailable"));
  const response = await handle(
    request("/api/auth/complete-siwe", proof, challengeCookie),
  );
  expect(response.status).toBe(500);
  expect(
    response.headers
      .getSetCookie()
      .some((value) => value.startsWith("worldAuth_refreshToken=")),
  ).toBe(false);
});
