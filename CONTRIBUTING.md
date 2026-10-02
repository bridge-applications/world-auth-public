# Contributing

Use Node 22+ and install the lockfile with `npm ci`. Run `npm run check` before submitting a change. Tests must not require production secrets, World App, Redis credentials, or network access. The dependency install itself requires access to the public npm registry.

For authentication changes, include tests for invalid input and failure behavior as well as the valid flow. Use real cryptographic primitives where practical; mock external wallet/RPC/Redis boundaries. Reproduce races with explicit deferred promises or shared barriers rather than timing sleeps. Keep logs and error messages free of credentials, decoded payloads, and configuration secrets.

Document changes to public types, endpoint contracts, token formats, cookies, and store semantics. Breaking protocol changes need migration notes and a major version. A passing coverage percentage does not establish that the security model is correct.

The release gate checks formatting, types, coverage, the packed package, and Workers runtime primitives. Publishing is manual. Review the generated tarball and migration notes, tag the intended version, and publish only from an account authorized to use the `@bridge-applications` npm scope. Never add registry credentials to this repository.

Miniflare 4 is the stable runtime used by the smoke test, targeting its supported `2026-08-06` compatibility date. Development-only overrides keep its undici and sharp dependencies on patched versions. Revisit these overrides when upgrading Miniflare; the smoke test must pass after any dependency change.
