import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createPublicClient, http } from "viem";
import { mainnet, worldchain } from "viem/chains";
import { createSiweMessage } from "viem/siwe";
import { verifyMessage } from "viem/actions";
import { verifyWalletProof } from "../src/logic/server/helpers/SiweService.js";
import { NOW, wallet } from "./fixtures.js";
vi.mock("viem/actions", () => ({ verifyMessage: vi.fn() }));
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
  vi.mocked(verifyMessage).mockReset().mockResolvedValue(true);
});
afterEach(() => vi.useRealTimers());
const context = {
  expectedNonce: "testnonce123",
  domain: "app.example",
  uri: "https://app.example",
};
function proof() {
  return {
    address: wallet,
    signature: "0x" + "ab".repeat(65),
    message: createSiweMessage({
      address: wallet,
      domain: context.domain,
      uri: context.uri,
      chainId: 480,
      version: "1",
      nonce: context.expectedNonce,
      issuedAt: new Date(NOW),
      expirationTime: new Date(NOW + 60_000),
      statement: "Sign in",
      requestId: "request-1",
    }),
  };
}
it("uses the configured RPC client and preserves the exact signed bytes", async () => {
  const client = createPublicClient({
    chain: worldchain,
    transport: http("https://rpc.example"),
  });
  const payload = proof();
  expect(
    await verifyWalletProof(
      payload,
      context.expectedNonce,
      { ...context, statement: "Sign in", requestId: "request-1" },
      client,
    ),
  ).toBe(true);
  expect(verifyMessage).toHaveBeenCalledWith(client, {
    address: wallet,
    message: payload.message,
    signature: payload.signature,
    mode: "eoa",
  });
});
it.each([
  ["domain", "app.example wants", "evil.example wants"],
  ["URI", "URI: https://app.example", "URI: https://evil.example"],
  ["chain", "Chain ID: 480", "Chain ID: 1"],
  ["nonce", "Nonce: testnonce123", "Nonce: differentnonce123"],
  ["version", "Version: 1", "Version: 2"],
  ["malformed issued-at", new Date(NOW).toISOString(), "not-a-date"],
  [
    "future issued-at",
    new Date(NOW).toISOString(),
    new Date(NOW + 30_001).toISOString(),
  ],
])(
  "rejects invalid %s before requesting signature verification",
  async (_label, before, after) => {
    const payload = proof();
    payload.message = payload.message.replace(before!, after!);
    expect(
      await verifyWalletProof(payload, context.expectedNonce, context),
    ).toBe(false);
    expect(verifyMessage).not.toHaveBeenCalled();
  },
);
it("rejects a wrong statement, request ID, wallet address, or malformed signature", async () => {
  for (const options of [
    { ...context, statement: "another statement" },
    { ...context, requestId: "other-request" },
  ])
    expect(
      await verifyWalletProof(proof(), context.expectedNonce, options),
    ).toBe(false);
  expect(
    await verifyWalletProof(
      { ...proof(), address: "0x" + "a".repeat(40) },
      context.expectedNonce,
      context,
    ),
  ).toBe(false);
  expect(
    await verifyWalletProof(
      { ...proof(), signature: "not-hex" },
      context.expectedNonce,
      context,
    ),
  ).toBe(false);
  expect(verifyMessage).not.toHaveBeenCalled();
});
it("rejects expired, not-yet-valid, or malformed lifetime fields", async () => {
  const expired = proof();
  vi.setSystemTime(NOW + 60_000);
  expect(await verifyWalletProof(expired, context.expectedNonce, context)).toBe(
    false,
  );
  vi.setSystemTime(NOW);
  const future = proof();
  future.message = future.message.replace(
    "\nRequest ID:",
    `\nNot Before: ${new Date(NOW + 1).toISOString()}\nRequest ID:`,
  );
  expect(await verifyWalletProof(future, context.expectedNonce, context)).toBe(
    false,
  );
  const invalid = proof();
  invalid.message = invalid.message.replace(
    new Date(NOW + 60_000).toISOString(),
    "not-a-date",
  );
  expect(await verifyWalletProof(invalid, context.expectedNonce, context)).toBe(
    false,
  );
  expect(verifyMessage).not.toHaveBeenCalled();
});
it("rejects a client configured for the wrong chain", async () => {
  const client = createPublicClient({ chain: mainnet, transport: http() });
  expect(
    await verifyWalletProof(proof(), context.expectedNonce, context, client),
  ).toBe(false);
  expect(verifyMessage).not.toHaveBeenCalled();
});
it("returns a rejected proof and lets RPC errors reach the server's fail-closed boundary", async () => {
  vi.mocked(verifyMessage)
    .mockResolvedValueOnce(false)
    .mockRejectedValueOnce(new Error("RPC unavailable"));
  expect(await verifyWalletProof(proof(), context.expectedNonce, context)).toBe(
    false,
  );
  await expect(
    verifyWalletProof(proof(), context.expectedNonce, context),
  ).rejects.toThrow("RPC unavailable");
});
