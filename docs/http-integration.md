# HTTP integration

The package does not register routes. Each success response uses `ApiBaseResSchema`: `status: "SUCCESS"`, `statusCode: 200`, `respCode: ApiResCodes.SUCCESS_REQUEST_COMPLETED`, and an application version. Endpoint fields are described by the schemas exported from `/schemas`. The numeric response-code enum is retained from the internal API; do not reorder its values.

| Default route             | Method | Application behavior                                                                                                            |
| ------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `/api/auth/nonce`         | GET    | Generate a nonce, bind it to a trusted session, return nonce and `nonceExpiresAt`.                                              |
| `/api/auth/complete-siwe` | POST   | Check origin, validate body, verify session-bound proof, resolve user, set refresh cookie, return access token and user fields. |
| `/api/auth/access-token`  | POST   | Check origin, verify HttpOnly refresh cookie, authorize the account, return a short-lived access token.                         |
| `/api/auth/sign-out`      | POST   | Check origin. Invalidate the user's refresh group when `signAllOut` is true, then clear the cookie.                             |
| `/api/auth/clear-cookies` | POST   | Check origin and clear cookies. This alone does not revoke copied refresh credentials.                                          |
| `/api/auth/app-session`   | POST   | Optional privileged application flow. Never expose user-ID-based issuance without explicit authorization.                       |

Apply HTTPS, request-body limits, rate limiting, CSRF protection, and a strict CORS policy at the application boundary. For same-origin browser requests, reject state-changing requests unless their Origin header exactly matches the configured public origin. Do not trust an arbitrary Host or forwarded header to define your expected SIWE domain. Cross-origin deployments require their own carefully tested cookie and CORS policy; the provided Strict cookie defaults target same-origin deployments.

Do not expose a refresh token in a JSON response. Store it only in an HttpOnly cookie and verify it server-side. Read the challenge cookie/session separately from the body nonce. Remove the challenge cookie after the completion attempt; a new attempt can obtain a new challenge. Never return credentials for an address submitted without successful wallet verification.

The included Fetch API example maps the verified wallet address to its own user identity to keep the example self-contained. Replace that with a user/account lookup and authorization check in an application. Add application-level handling for disabled accounts, token claims that become stale, production request logs, and abuse controls.
