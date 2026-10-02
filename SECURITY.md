# Security policy

Report authentication bypasses, credential disclosure, replay, cryptographic issues, and unsafe default behavior privately to the maintainer. Use [GitHub private vulnerability reporting](https://github.com/bridge-applications/world-auth-public/security/advisories/new) when available. If private reporting has not been enabled, contact the maintainer through the contact information on the [GitHub profile](https://github.com/tspunt). Do not publish a working exploit or credentials in a public issue.

Include the package/runtime versions, the affected configuration (with secrets removed), reproduction steps, expected/actual behavior, and impact. Use test-only keys and accounts. Never submit real user tokens or personal data.

The current 2.0 release candidate is the public development line. Internal 1.x deployments require a coordinated migration; see the migration guide. This project does not claim an independent security audit. Consumers are responsible for reviewing the integration's session binding, stores, route authorization, and deployment controls.
