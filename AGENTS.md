# Agent guidance

## Project purpose and boundaries

`@bridge-applications/world-auth` is a TypeScript library for World mini-app wallet authentication, SIWE verification, signed challenges, and encrypted access and refresh tokens. The host application owns user records, permissions, HTTP routes, session binding, and deployment controls.

Read `CONTRIBUTING.md` before making changes. Consult `docs/architecture.md` for authentication and operational contracts, `docs/http-integration.md` for HTTP integration, and `SECURITY.md` for vulnerability reporting. Keep these documents consistent with changes to the library.

## Code map and dependency boundaries

- `src/logic/client/`: browser authentication state and backend requests.
- `src/logic/server/`: server instances, nonce signing, wallet-proof verification, and token handling.
- `src/schemas/`: shared validators and HTTP request/response contracts.
- `src/client.ts`, `src/server.ts`, `src/schemas.ts`, and `src/index.ts`: public package entry points.
- `tests/`: authentication, integration, and failure-path tests.
- `scripts/`: packed-package checks and Workers runtime smoke tests.
- `examples/` and `docs/`: integration examples and consumer documentation.

Preserve the dedicated entry points. The browser `/client` entry must not import the MiniKit SDK, Redis, jose, viem, or Node crypto; the host supplies MiniKit through an adapter. Shared `/schemas` must remain free of server dependencies. The root entry exports both client and server APIs for compatibility.

## Development and verification

Use Node.js 22 or newer and install dependencies from the lockfile with `npm ci`.

Run `npm run check` before submitting code changes. It checks formatting, TypeScript, test coverage, the packed package and its consumers, browser bundle isolation, and Workers runtime primitives. Useful focused commands are:

- `npm run typecheck`
- `npm test`
- `npm run test:coverage`
- `npm run test:package`
- `npm run test:workers`
- `npm run format:check`

Tests must run without production secrets, World App, Redis credentials, or network access. Dependency installation requires the public npm registry. Report which checks ran, their results, and any checks that could not run; do not claim unverified checks passed.

For documentation-only changes, check formatting and verify referenced commands, paths, and behavior against the repository. Do not add tests that merely repeat documentation.

## Code conventions

Follow the surrounding code and existing naming patterns. Use strict TypeScript, ESM imports with `.js` extensions for relative module paths, and explicit type-only imports where appropriate. Preserve schema-derived public types and runtime validation at trust boundaries.

Use Prettier for formatting. Format changed files rather than introducing unrelated formatting changes. Edit source files rather than generated `dist/` output.

## Authentication invariants

Preserve these contracts when changing authentication code:

- Require a challenge bound to trusted application session state. Expected nonce, domain, URI, and chain context must come from trusted configuration or session state, never from the submitted proof.
- Consume nonces atomically across server instances only after successful wallet-proof verification. Invalid proofs must not consume challenges. Reject replay and verifier/store failures.
- Keep token purpose, namespace, version, cryptographic algorithm, timestamp, identity, and payload-schema validation intact. Access and refresh credentials are not interchangeable.
- Reject malformed refresh-group counters and store failures. Invalidation must atomically increment the current counter. Group counters must never expire or be evicted, because losing them can restore validity to old credentials.
- Preserve browser session-generation checks so late responses cannot restore authentication after logout, reset, or reinitialization. Concurrent refresh requests within a generation share one in-flight request.
- Keep refresh credentials out of browser storage. Preserve secure cookie defaults and matching deletion scope; cookie `maxAge` is measured in seconds.
- Never log credentials, decoded authentication payloads, wallet proofs, configuration secrets, or sensitive response bodies. Use synthetic keys and accounts in tests and examples.

Wallet authentication establishes control of a wallet. It does not establish World ID verification or grant application permissions. Refresh-group invalidation is user-wide and does not implement single-use refresh-token rotation or revoke existing access tokens.

## Tests and consumer documentation

For authentication changes, test invalid input and failure behavior as well as the successful flow. Use real cryptographic primitives where practical and mock external wallet, RPC, and Redis boundaries. Reproduce races with deferred promises or shared barriers rather than timing sleeps. Coverage percentages alone do not establish security correctness.

Update relevant documentation and examples when changing public types, endpoint contracts, token formats, cookies, or store semantics. Breaking protocol changes require migration notes and a major release; identify that requirement without changing the version unless explicitly requested.

After dependency changes, run the full checks, including the Workers smoke test. Review the documented Miniflare dependency overrides when upgrading that runtime.

## Scope and release boundaries

Keep changes focused on the requested task and preserve unrelated work. Explain material behavior changes, verification results, and unresolved limitations in the handoff.

Publishing packages, tagging releases, and changing package versions require an explicit user request. Never add registry credentials or production secrets to the repository. Follow `CONTRIBUTING.md` for an authorized release and `SECURITY.md` for private vulnerability reporting.
