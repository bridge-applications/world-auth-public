import { vi } from "vitest";
import { z } from "zod";
import type {
  NonceStore,
  TokenGroupStore,
  WorldAuthServerConfig,
} from "../src/server.js";
export const NOW = Date.UTC(2026, 9, 2, 12);
export const wallet = "0x1234567890123456789012345678901234567890";
export const payloadSchema = z.object({
  userId: z.string().min(1),
  role: z.enum(["member", "admin"]).default("member"),
});
export function memoryGroups() {
  const values = new Map<string, unknown>();
  const store = {
    get: vi.fn(
      async (key: string): Promise<unknown> => values.get(key) ?? null,
    ),
    incr: vi.fn(async (key: string) => {
      const next = Number(values.get(key) ?? 0) + 1;
      values.set(key, next);
      return next;
    }),
  } satisfies TokenGroupStore;
  return { values, store };
}
export function memoryNonces() {
  const used = new Set<string>();
  return {
    consume: vi.fn(async (nonce: string, expiresAtMs: number) => {
      if (Date.now() >= expiresAtMs || used.has(nonce)) return false;
      used.add(nonce);
      return true;
    }),
  } satisfies NonceStore;
}
export function config() {
  return {
    secrets: { nonceSecret: "n".repeat(32), jweSecret: "k".repeat(32) },
    namespace: "test-app",
    accessTokenConfig: { ttlMs: 60_000, payloadSchema },
    refreshTokenConfig: { ttlMs: 3_600_000, payloadSchema, idField: "userId" },
    tokenGroupStore: memoryGroups().store,
    nonceStore: memoryNonces(),
  } satisfies WorldAuthServerConfig;
}
export function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
