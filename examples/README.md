# Fetch API authentication integration

`fetch-handler.ts` provides a same-origin Request/Response integration for a configured `WorldAuthServer`. It is typechecked and its login/refresh/logout behavior is exercised by the test suite. It can be adapted to Node servers, framework routes, or Workers.

Configure the server with JSON-compatible `{ userId: string, walletAddress: string }` payload schemas, shared nonce/revocation stores, and secrets from the deployment environment. Call `createAuthHandler(auth, "https://your-app.example")` and route incoming authentication requests to its returned function. Pass the configured public origin, not a value supplied in request headers. The browser must send JSON bodies and same-origin credentials; the package client supplies these.

The example uses the verified wallet address as its own user ID so it does not depend on a database. Replace this with your application's user lookup and permission checks at login and refresh. There is deliberately no user-ID-only administrative login route. Add deployment rate limits, request logging that redacts secrets, and abuse controls. Secure cookies require HTTPS, including for browser integration tests.

`npm test` checks this handler without a native wallet, Redis service, or external network. `npm run test:workers` separately checks the package's crypto/token primitives in workerd with `nodejs_compat`.
