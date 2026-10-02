# Migrating from the internal 1.x package

2.0 introduces stricter contracts and a new token/nonce format. Deploy it as an authentication migration, not a transparent library substitution. Keep the private 1.x source and release history available for applications still on the old protocol.

1. Move frontend imports to `/client` and backend imports to `/server`. Upgrade to MiniKit 2, Zod 4, Node 22+, and ESM. The earlier CommonJS export declaration did not provide a separate CommonJS build; 2.0 no longer advertises one.
2. Set a stable namespace per application/environment. Provision independent random nonce and JWE secrets. JWE keys may be supplied as 32 decoded bytes.
3. Configure a shared nonce store and token-group store. Redis supplies both. Remove any expiration/eviction policy for refresh group counters. The key format now hashes user identities and includes the namespace.
4. Bind every challenge to the browser session. Pass trusted `expectedNonce`, `domain`, and `uri` to `verifySiwe`; it no longer accepts a two-argument verification call. Challenges must be consumed atomically. Missing stores and replay fail closed.
5. Update the completion request to require `nonce` and a wallet proof. The former `walletProfile` impersonation field has been removed. Any administrative session or impersonation flow must have separate explicit server authorization; possession of a submitted wallet address is never sufficient.
6. Plan a coordinated browser/server rollout that clears the old refresh cookie and asks users to sign in again. **1.x tokens and challenges are not accepted by 2.0.** Do not silently accept both purposes or formats. If a staged rollout is necessary, keep separate routes/cookies for the old application version and retire them on a defined schedule.
7. Browser token storage is now opt-in and uses one validated entry (`worldAuth.tokens` by default). Old `worldAuth_accessToken`, `worldAuth_accessTokenExpiresAt`, and `worldAuth_refreshTokenExpiresAt` entries are not migrated. Remove them in the application rollout. Confirm your XSS policy before enabling persistence.
8. `getAppSession` now validates `{ userId }` as its default request. Its route remains privileged and must implement your authorization policy. Error responses, including ERROR envelopes returned with HTTP 200, no longer commit credentials.
9. Adapt cookie callbacks: `maxAge` is explicitly seconds and asynchronous writers are awaited. In Express, multiply by 1000. Clear helpers include matching secure attributes and maxAge=0.
10. `rotateRefreshTokenGroup` verifies the credential before invalidation and increments the live counter. It throws if group verification is disabled. It invalidates refresh credentials for the entire identity, not already issued access tokens.

Refresh/access payload schemas must accept JSON-serialized validated output. Optional access payloads now round trip as `null` when no schema is configured. Invalid payloads, token-purpose mismatch, exact-boundary expiry, malformed Redis counters, and identity mismatch are rejected. Debug output no longer prints credentials or payloads.
