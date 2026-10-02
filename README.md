# @bridge-applications/world-auth

The open-source edition of Bridge Applications’ internal World wallet-authentication library. The library is used in production by **Pebbler World**, **Bridge**, and **five World mini games**, sharing authentication logic between browser clients and backend services.

Created and maintained by **[Tessel Punt](https://github.com/tspunt) at [Bridge Applications](https://github.com/bridge-applications)**.

The package handles MiniKit wallet commands, SIWE verification, signed challenges, encrypted access and refresh tokens, and user-wide refresh-token invalidation. The application owns its user database, permissions, HTTP routes, and deployment policy.

## Production usage

The package is integrated into:

- **[Pebbler World](https://world.org/ecosystem/app_0e3f2e07cf3fb2e43fdddbb73d21d355)** — a crypto micro-task app. It handles wallet sign-in, backend challenge verification, and access/refresh tokens across the browser client and backend.
- **[Bridge](https://world.org/ecosystem/app_443bd39e83f7ab076b200e630c70c772)** — a file-sharing app. It handles World wallet sign-in and access-token verification for file-transfer operations, including uploads, transfer completion, listing, and deletion.
- **HTCC / 120CC games** — [Brain Bus](https://world.org/ecosystem/app_911d07e15674a4450a3a749ea7eb502b), [UnScrewed!](https://world.org/ecosystem/app_ca7d2b3ff46067131f51586e59b50900), [Picture Jam](https://world.org/ecosystem/app_cf9dace7b0104a6a151e4e26c649de3b), [Match & Win](https://world.org/ecosystem/app_cc9e631ad8d8936d6a4b34a403689279), and [Color Jam](https://world.org/ecosystem/app_16603dd89b5aaa23c802002c0d430b1e) share wallet sign-in and authenticated sessions through `@bridge-applications/htcc-kit`, which integrates `WorldAuthClient`. The shared backend uses `WorldAuthServer` for challenge generation, SIWE verification, and access/refresh token issuance and verification.

## Installation

```sh
npm install @bridge-applications/world-auth zod
```

Requires Node.js 22 or newer and Zod 4. The browser client uses fetch, AbortController, and Web Crypto. MiniKit 2 is supported. This release is ESM only.

Use the dedicated entry points so browser builds do not include server code:

```ts
import { WorldAuthClient } from "@bridge-applications/world-auth/client";
import { WorldAuthServer } from "@bridge-applications/world-auth/server";
import { ApiStatus } from "@bridge-applications/world-auth/schemas";
```

The root entry point exports both client and server APIs for compatibility. Prefer `/client` in frontend code.

## Server setup

```ts
import { z } from "zod";
import { WorldAuthServer } from "@bridge-applications/world-auth/server";

const sessionSchema = z.object({
  userId: z.string().min(1),
  walletAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
});

const auth = await WorldAuthServer.create({
  namespace: "my-mini-app",
  secrets: {
    nonceSecret: process.env.WORLD_AUTH_NONCE_SECRET!,
    jweSecret: Buffer.from(process.env.WORLD_AUTH_JWE_KEY_BASE64!, "base64"),
  },
  redisConfig: {
    redisUrl: process.env.UPSTASH_REDIS_REST_URL!,
    redisToken: process.env.UPSTASH_REDIS_REST_TOKEN!,
  },
  accessTokenConfig: { ttlMs: 5 * 60_000, payloadSchema: sessionSchema },
  refreshTokenConfig: {
    ttlMs: 7 * 24 * 60 * 60_000,
    payloadSchema: sessionSchema,
    idField: "userId",
  },
});
```

Use two independent random secrets. `jweSecret` accepts exactly 32 bytes, either as a Uint8Array or a UTF-8 string. `nonceSecret` requires at least 32 UTF-8 bytes. Generate secrets outside the repository, store them in your platform's secret manager, and use a distinct namespace and secrets for each application and environment.

Redis provides atomic nonce consumption and refresh-token group counters. Custom stores can implement `NonceStore` and `TokenGroupStore`. The stores must be shared by every server instance. `WorldAuthServer.create()` returns an independent instance; `init()` reuses an instance only when passed the same configuration object. Treat schemas and configuration as immutable after initialization.

## Wallet login

1. Generate a challenge with `auth.genNonce()`. Store its nonce in a trusted server session or a Secure, HttpOnly challenge cookie, and return `{ nonce, nonceExpiresAt }` in the API response envelope.
2. Call `MiniKit.walletAuth()` in the browser, using that nonce.
3. Validate the completion request, retrieve the session's challenge independently of the request body, and verify the proof:

```ts
const valid = await auth.verifySiwe(payload, nonce, {
  expectedNonce: sessionNonce,
  domain: "my-app.example",
  uri: "https://my-app.example",
  chainId: 480,
});
```

`domain`, `uri`, and `expectedNonce` must come from trusted application configuration/session state. Do not derive them from the submitted proof. The verifier checks application context and wallet address, verifies the wallet proof through viem, and atomically consumes the nonce. It returns false on invalid proof, replay, missing nonce store, or verifier/store failure. Failed wallet proofs do not consume a challenge.

Only after successful verification should the application resolve its user record and issue tokens. Wallet authentication establishes control of a wallet; it does not establish World ID verification or grant application permissions. The optional statement/request ID checks are available when those values are also maintained server-side.

## Browser client

```ts
import { MiniKit } from "@worldcoin/minikit-js";
import { WorldAuthClient } from "@bridge-applications/world-auth/client";

WorldAuthClient.init({
  baseUrl: "https://my-app.example",
  miniKit: MiniKit,
  defaultStatement: "Sign in to My App",
});

await WorldAuthClient.walletAuth();
const { accessToken } = await WorldAuthClient.getAccessTokenSilently();
// Send the credential to your protected API over HTTPS.
await WorldAuthClient.signOut({ signAllOut: true });
```

Initialize MiniKit according to its own installation guidance before invoking wallet commands. Native MiniKit and wagmi results are accepted; fallback and malformed results are rejected. The client validates requests/responses and sends requests with `credentials: "include"`.

Access tokens are held in memory by default. To persist them, explicitly pass `storage: window.sessionStorage` or `window.localStorage` and an application-specific `storageKey`. Browser storage is readable by scripts on your origin; it is not a substitute for XSS protection. The client never stores the refresh-token credential in browser storage. A remembered refresh expiry is only a UI hint: the server still verifies the HttpOnly cookie.

Concurrent refresh requests share one in-flight request. Logout clears local state immediately, including when its HTTP request fails. Late token responses after logout, reset, or reinitialization are rejected. A failed logout request can leave a valid server cookie; handle that error and retry the server operation. `reset()` only detaches the client instance; it is not server logout or persistent-storage removal.

The default request timeout is 15 seconds. Configure `requestTimeoutMs`, `urlPaths`, and `customSchemas` for application-specific contracts. `completeSiwe()` supports `{ deferCommit: true }` followed by `commitAuth()` when the application needs to commit several related states together.

## Tokens, cookies, and invalidation

Access and refresh credentials are compact encrypted JWE tokens using direct A256GCM encryption. Their versioned envelope includes token purpose and application namespace. A refresh token cannot be used as an access token. Metadata timestamps are milliseconds; these are not standard JWT `exp`/`iat` claims.

```ts
const access = await auth.genAccessToken({ userId, walletAddress });
const refresh = await auth.genRefreshToken({ userId, walletAddress });
const verified = await auth.verifyAccessToken(access.accessToken);
// verified.payload is inferred from the configured Zod schema.

await auth.rotateRefreshTokenGroup(refresh.refreshToken);
```

`rotateRefreshTokenGroup()` invalidates all existing refresh credentials for the token's user. It does not issue a replacement credential or implement single-use refresh-token rotation. Existing access tokens remain valid until expiry; keep their lifetime short. New refresh tokens use the current stored group. Store errors and malformed counters fail closed. Never expire or evict group keys: losing a counter could make older group-zero credentials valid again.

`skipTokenGroupVerification: true` explicitly disables user-wide revocation and makes the invalidation method throw. A nonce store is still required for wallet login. A payload-free access token is supported, but contains no user identity and should not authorize user-specific operations.

Cookie helpers use `worldAuth_refreshToken`, HttpOnly, Secure, SameSite=Strict, and path `/`. `maxAge` is in **seconds**; multiply by 1000 in Express adapters. Cookie deletion uses the same scope. The helpers do not implement CSRF protection, CORS, rate limits, route authorization, or a session database. See [HTTP integration](docs/http-integration.md) and the [Fetch API example](examples/README.md).

Diagnostics print only event/status metadata. Never log authentication payloads or credentials in application middleware. `WorldAuthError.code` identifies token validation failures; `WorldAuthApiError.code` distinguishes transport, timeout, and contract failures without echoing sensitive response bodies.

Server wallet verification uses viem's SIWE parser and signature verifier to avoid MiniKit 2.0.3's verbose RPC-error logging. The default World Chain transport has a 10-second timeout and no retries. Pass `siweClient` in server configuration to use your own RPC transport; its chain must match the expected chain. SIWE messages must have a valid issued-at timestamp, with at most 30 seconds of forward clock skew.

## Runtime and development

```sh
npm ci
npm run check
```

The checks include TypeScript, unit tests with coverage thresholds, a real signed SIWE proof, packed-package ESM/type consumers, browser bundle isolation, and a Miniflare Workers smoke test. Redis and network failure boundaries are mocked in unit tests; the suite does not require production credentials or a running Redis service.

Cloudflare Workers require `nodejs_compat` for Node crypto/Buffer support. The runtime smoke test covers challenge signing and token encryption/verification. Wallet verification can perform an RPC request for contract wallets; provision and monitor that dependency in your deployment. Browser/client tests use a MiniKit adapter rather than a native World App session.

See [architecture](docs/architecture.md), [migration from 1.x](docs/migration-v2.md), [contributing](CONTRIBUTING.md), and [security reporting](SECURITY.md).
