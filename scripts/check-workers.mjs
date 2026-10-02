import assert from "node:assert/strict";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { resolve } from "node:path";

const bundled = await build({
  stdin: {
    contents: `
    import { WorldAuthServer } from './dist/server.js';
    import { z } from 'zod';
    export default { async fetch() {
      const auth = await WorldAuthServer.create({ secrets: { nonceSecret: 'n'.repeat(32), jweSecret: 'k'.repeat(32) }, namespace: 'worker-test', accessTokenConfig: { ttlMs: 60000, payloadSchema: z.object({ userId: z.string() }) }, refreshTokenConfig: { ttlMs: 60000, payloadSchema: z.object({ userId: z.string() }), idField: 'userId', skipTokenGroupVerification: true } });
      const challenge = await auth.genNonce();
      const access = await auth.genAccessToken({ userId: 'test-user' });
      const refresh = await auth.genRefreshToken({ userId: 'test-user' });
      return Response.json({ nonceValid: auth.verifyNonce(challenge.nonce).valid, access: (await auth.verifyAccessToken(access.accessToken)).payload, refresh: (await auth.verifyRefreshToken(refresh.refreshToken)).payload });
    } };
  `,
    resolveDir: resolve(import.meta.dirname, ".."),
    sourcefile: "worker-smoke.ts",
  },
  bundle: true,
  platform: "neutral",
  format: "esm",
  conditions: ["workerd", "import"],
  external: ["node:*"],
  write: false,
});
const worker = new Miniflare({
  modules: true,
  script: bundled.outputFiles[0].text,
  // Stable Miniflare 4's pinned workerd supports compatibility dates through this date.
  compatibilityDate: "2026-08-06",
  compatibilityFlags: ["nodejs_compat"],
});
try {
  const response = await worker.dispatchFetch("https://test.example");
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    nonceValid: true,
    access: { userId: "test-user" },
    refresh: { userId: "test-user" },
  });
  console.log(
    "Workers runtime: nonce signing and encrypted access/refresh token round trips passed.",
  );
} finally {
  await worker.dispose();
}
