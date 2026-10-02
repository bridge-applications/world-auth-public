# Changelog

## 2.0.0-rc.1

Public release preparation based on Bridge Applications' internal 1.2.0 package.

- Add browser, server, and shared-schema entry points with ESM declarations.
- Introduce versioned, purpose-bound, application-scoped encrypted token envelopes.
- Fix payload-free access tokens and return validated payload data consistently.
- Require trusted session/application context and atomic nonce consumption for wallet login.
- Use atomic shared refresh-group increments and reject malformed store state.
- Isolate server initialization by configuration identity instead of schema property names.
- Deduplicate browser refresh requests and reject commits after session invalidation.
- Make browser persistence opt-in, handle storage failures, and bound HTTP requests.
- Remove credential/payload logging and the completion request's impersonation field.
- Add unit/integration tests, packed-consumer checks, Workers runtime checks, and migration documentation.

1.x tokens and challenges require a new sign-in. See `docs/migration-v2.md` before upgrading a live application.
