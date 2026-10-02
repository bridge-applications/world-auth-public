import {
  ApiAuthCompleteSiweReqSchema,
  ApiAuthSignOutReqSchema,
  ApiResCodes,
  ApiStatus,
  HttpStatusCodes,
} from "../src/schemas.js";
import { WorldAuthError } from "../src/server.js";
import type { WorldAuthServer } from "../src/server.js";

export interface SessionClaims {
  userId: string;
  walletAddress: string;
}
const challengeCookie = "__Host-worldAuth_nonce";
class InvalidRequestError extends Error {}

function cookie(request: Request, name: string): string | null {
  const values = (request.headers.get("cookie") ?? "")
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.startsWith(`${name}=`));
  // Duplicate cookie names are ambiguous; do not select an attacker-controlled one.
  return values.length === 1 ? values[0]!.slice(name.length + 1) : null;
}
function serialize(name: string, value: string, maxAge: number): string {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}
async function readJson(request: Request): Promise<unknown> {
  if (
    !request.headers
      .get("content-type")
      ?.toLowerCase()
      .startsWith("application/json")
  )
    throw new InvalidRequestError("Expected JSON");
  const reader = request.body?.getReader();
  if (!reader) throw new InvalidRequestError("Missing request body");
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > 16_384) {
        await reader.cancel();
        throw new InvalidRequestError("Request body exceeds 16 KiB");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return JSON.parse(new TextDecoder().decode(bytes));
}

/** Same-origin integration. Supply account lookup/authorization before issuing application claims. */
export function createAuthHandler(
  auth: WorldAuthServer<SessionClaims, SessionClaims>,
  publicOrigin: string,
) {
  const origin = new URL(publicOrigin);
  if (origin.protocol !== "https:" || origin.origin !== publicOrigin)
    throw new Error("publicOrigin must be an HTTPS origin");
  return async (request: Request): Promise<Response> => {
    const headers = new Headers({ "Cache-Control": "no-store" });
    const result = (fields: object, status = HttpStatusCodes.OK) =>
      Response.json(
        {
          status: status === 200 ? ApiStatus.SUCCESS : ApiStatus.ERROR,
          statusCode: status,
          respCode:
            status === 200
              ? ApiResCodes.SUCCESS_REQUEST_COMPLETED
              : ApiResCodes.ERROR_ACCESS_DENIED,
          version: "example",
          ...fields,
        },
        { status, headers },
      );
    const path = new URL(request.url).pathname;
    if (
      request.method !== "GET" &&
      request.headers.get("origin") !== origin.origin
    )
      return result({}, HttpStatusCodes.FORBIDDEN);
    try {
      if (path === "/api/auth/nonce" && request.method === "GET") {
        const { nonce, expiresAtMs } = await auth.genNonce();
        headers.append(
          "Set-Cookie",
          serialize(
            challengeCookie,
            nonce,
            Math.max(0, Math.floor((expiresAtMs - Date.now()) / 1000)),
          ),
        );
        return result({ nonce, nonceExpiresAt: expiresAtMs });
      }
      if (path === "/api/auth/complete-siwe" && request.method === "POST") {
        headers.append("Set-Cookie", serialize(challengeCookie, "", 0));
        const parsed = ApiAuthCompleteSiweReqSchema.safeParse(
          await readJson(request),
        );
        const expectedNonce = cookie(request, challengeCookie);
        if (!parsed.success || !expectedNonce)
          return result({}, HttpStatusCodes.BAD_REQUEST);
        const { nonce, payload } = parsed.data;
        if (
          !(await auth.verifySiwe(payload, nonce, {
            expectedNonce,
            domain: origin.host,
            uri: origin.origin,
          }))
        )
          return result({}, HttpStatusCodes.UNAUTHORIZED);
        // In an application, resolve this verified wallet to a user/account record and check access.
        const claims = {
          userId: payload.address.toLowerCase(),
          walletAddress: payload.address,
        };
        const refresh = await auth.genRefreshToken(claims);
        const access = await auth.genAccessToken(claims);
        await auth.setRefreshTokenCookie(
          refresh.refreshToken,
          refresh.refreshTokenExpiresAt,
          (options) => {
            headers.append(
              "Set-Cookie",
              serialize(options.name, options.value, options.maxAge),
            );
          },
        );
        return result({
          ...access,
          refreshTokenExpiresAt: refresh.refreshTokenExpiresAt,
          ...claims,
        });
      }
      if (path === "/api/auth/access-token" && request.method === "POST") {
        const refresh = auth.getRefreshTokenCookie((name) =>
          cookie(request, name),
        );
        if (!refresh) return result({}, HttpStatusCodes.UNAUTHORIZED);
        const { payload } = await auth.verifyRefreshToken(refresh);
        // Recheck the account/permissions here before issuing a new access credential.
        return result(await auth.genAccessToken(payload));
      }
      if (path === "/api/auth/sign-out" && request.method === "POST") {
        const options = ApiAuthSignOutReqSchema.safeParse(
          await readJson(request),
        );
        if (!options.success) return result({}, HttpStatusCodes.BAD_REQUEST);
        const refresh = auth.getRefreshTokenCookie((name) =>
          cookie(request, name),
        );
        if (options.data.signAllOut && refresh) {
          try {
            await auth.rotateRefreshTokenGroup(refresh);
          } catch (error) {
            if (
              !(error instanceof WorldAuthError) ||
              error.code === "INVALID_TOKEN_GROUP"
            )
              throw error;
          }
        }
        await auth.clearRefreshTokenCookie((name) => {
          headers.append("Set-Cookie", serialize(name, "", 0));
        });
        return result({ success: true });
      }
      if (path === "/api/auth/clear-cookies" && request.method === "POST") {
        await auth.clearRefreshTokenCookie((name) => {
          headers.append("Set-Cookie", serialize(name, "", 0));
        });
        headers.append("Set-Cookie", serialize(challengeCookie, "", 0));
        return result({ success: true });
      }
      return result({}, HttpStatusCodes.NOT_FOUND);
    } catch (error) {
      if (error instanceof WorldAuthError)
        return result({}, HttpStatusCodes.UNAUTHORIZED);
      if (error instanceof SyntaxError || error instanceof InvalidRequestError)
        return result({}, HttpStatusCodes.BAD_REQUEST);
      return result({}, HttpStatusCodes.INTERNAL_SERVER_ERROR);
    }
  };
}
