# Architecture and operational contracts

## Boundaries

`/client` contains the browser session state machine and API schemas. MiniKit is supplied by the host application; importing this entry does not import the SDK, Redis, jose, viem, or Node crypto. `/server` owns cryptographic verification and token issuance. The viem verifier is imported when wallet verification is invoked. MiniKit wallet command results remain the browser integration contract. `/schemas` contains the HTTP contracts without server dependencies.

The client is a singleton within one browser realm, matching an application with one authentication context. Server instances are application-scoped and independent. The `init` cache is a WeakMap keyed by the exact configuration object, so schemas with the same property names cannot collide and cache keys do not serialize credentials. `create` always returns a new instance. Cryptographic keys and token configuration are copied at construction; schema and store objects remain trusted application dependencies.

## Challenges

A challenge contains 16 random bytes, an expiry encoded in base 36, and a truncated 128-bit HMAC-SHA256 signature. All characters are alphanumeric for MiniKit. Expiry is rounded down to a whole second; the returned timestamp matches the encoded expiry. Nonce TTL is bounded to 1 second through 15 minutes, with a 5-minute default. Verification rejects at the exact expiry boundary.

Challenge signatures only establish issuance and expiry. A complete login also requires the nonce bound to the browser session, a valid wallet signature for the expected application/chain, and a successful atomic consumption operation. Redis consumption uses SET NX with a TTL through nonce expiry and a SHA-256 key instead of the raw nonce. A custom nonce store must provide the same atomicity across processes. An in-memory store is suitable for isolated tests, not a distributed deployment.

## Token envelope

Tokens contain `{ v: 2, kind, aud, payload, meta }`. The authenticated JWE protected header includes `typ: world-auth/access` or `world-auth/refresh`. Decryption restricts algorithms to `dir` and `A256GCM`. Verification checks header type, envelope version, purpose, namespace, timestamps, and the configured payload schema. Refresh verification also checks identity consistency and the shared group counter.

Payload schemas must accept their JSON-serialized output. Avoid Date, BigInt, cyclic values, and non-idempotent transformations; use JSON-compatible claims with defaults/refinements. Generation strips unknown object properties according to the schema. The verifier returns validated data, rather than returning an unchecked decrypted object. Verification never logs plaintext or token values.

## Group counters

Keys are `<namespace>:rtg:<SHA-256(user identity)>`. A missing key starts at group zero. Counters are safe nonnegative integers; invalid values and store errors reject authentication. Group invalidation verifies the supplied refresh token and atomically increments the current store value. Concurrent invalidations may increment more than once; they never write a token's stale saved counter over a newer value.

Retain group counters permanently and configure persistence/no eviction for this state. Group invalidation is a user-wide mechanism, not session-specific revocation. A verification racing with an invalidation may have already read the previous group; the application must decide whether stronger transactional authorization is needed for a sensitive operation. Authorization, account suspension, and role changes remain application responsibilities.

## Browser state

Token-bearing responses commit only if the originating client and its session generation are still current. Logout advances that generation before sending its HTTP request. Reinitialization/reset also invalidate pending operations. Refreshes within the same generation share a promise; failures release it for a later retry. This prevents late requests from restoring local authentication after logout, but does not cancel a server-side operation already in progress or revoke its cookie.

Storage is optional. It contains the access token, access expiry, and refresh expiry; it never contains the refresh credential. Reads and writes tolerate embedded-browser storage exceptions. Entries are validated before reuse. `isAuthenticated` reflects a locally unexpired access credential, not a successful server authorization check. `expectedToBeAuthenticated` only reflects a remembered refresh expiry.

## Verification scope

Tests exercise real JWE encryption and decryption, nonce signing, an EOA SIWE signature through the installed viem verifier, deterministic races, mocked Redis protocol calls, and packed artifacts. The Workers smoke test covers the cryptographic primitives in workerd. It does not validate a deployed application's cookies/CORS, native wallet interactions, real Redis persistence, or contract-wallet RPC availability. Those need integration checks in the application environment.
