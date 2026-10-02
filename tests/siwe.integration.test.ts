import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { createSiweMessage } from "viem/siwe";
import { WorldAuthServer } from "../src/server.js";
import { config, NOW } from "./fixtures.js";
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
});
afterEach(() => vi.useRealTimers());

it("verifies a real EOA signature through viem and rejects a changed signed message", async () => {
  // Ephemeral test-only key, never an account used by an application.
  const account = privateKeyToAccount(
    ("0x" + "01".repeat(32)) as `0x${string}`,
  );
  const auth = await WorldAuthServer.create(config());
  const challenge = await auth.genNonce();
  const options = {
    expectedNonce: challenge.nonce,
    domain: "app.example",
    uri: "https://app.example",
    statement: "Sign in to the test application",
  };
  const message = createSiweMessage({
    address: account.address,
    domain: options.domain,
    uri: options.uri,
    version: "1",
    chainId: 480,
    nonce: challenge.nonce,
    issuedAt: new Date(NOW),
    expirationTime: new Date(challenge.expiresAtMs),
    statement: options.statement,
  });
  const signature = await account.signMessage({ message });
  // A tampered message must never fall through to a real RPC during this test.
  const fetch = vi
    .fn()
    .mockRejectedValue(new Error("External network disabled in tests"));
  vi.stubGlobal("fetch", fetch);
  const payload = {
    status: "success",
    version: 1,
    address: account.address,
    message,
    signature,
  };
  expect(await auth.verifySiwe(payload, challenge.nonce, options)).toBe(true);
  expect(fetch).not.toHaveBeenCalled();
  expect(
    await auth.verifySiwe(
      { ...payload, message: message.replace("app.example", "evil.example") },
      challenge.nonce,
      options,
    ),
  ).toBe(false);
});
