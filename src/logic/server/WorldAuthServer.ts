import { createHash, timingSafeEqual } from "node:crypto";
import { Redis } from "@upstash/redis";
import type { z } from "zod";
import type { Client } from "viem";
import { NonceService } from "./helpers/NonceService.js";
import { TokenService } from "./helpers/TokenService.js";
import type { TokenGroupStore } from "./helpers/TokenService.js";

export interface NonceStore {
  /** Atomically return true once per nonce, retaining the marker until expiresAtMs. */
  consume(nonce: string, expiresAtMs: number): Promise<boolean>;
}

export interface SiweVerificationOptions {
  /** A nonce read from a trusted server session or HttpOnly challenge cookie. */
  expectedNonce: string;
  domain: string;
  uri: string;
  chainId?: number;
  statement?: string;
  requestId?: string;
}

export interface WorldAuthServerConfig<A = unknown, R = unknown> {
  /** Override the World Chain RPC client for contract-wallet signature verification. */
  siweClient?: Client;
  secrets: { nonceSecret: string; jweSecret: string | Uint8Array };
  namespace?: string;
  redisConfig?: { redisUrl: string; redisToken: string };
  tokenGroupStore?: TokenGroupStore;
  nonceStore?: NonceStore;
  accessTokenConfig: { ttlMs: number; payloadSchema?: z.ZodType<A> };
  refreshTokenConfig: {
    ttlMs: number;
    payloadSchema: z.ZodType<R>;
    idField: string;
    skipTokenGroupVerification?: boolean;
    debug?: boolean;
  };
  debug?: boolean;
}

export interface RefreshCookieOptions {
  name: "worldAuth_refreshToken";
  value: string;
  httpOnly: true;
  secure: true;
  sameSite: "Strict";
  path: "/";
  /** Seconds. Express adapters must multiply by 1000. */
  maxAge: number;
}

type CookieWriter = (options: RefreshCookieOptions) => void | Promise<void>;
type CookieClearer = (
  name: string,
  options: Omit<RefreshCookieOptions, "name" | "value">,
) => void | Promise<void>;

/** Application-scoped verifier. Create once with stable secrets and a shared revocation store. */
export class WorldAuthServer<A = unknown, R = unknown> {
  private static readonly instances = new WeakMap<
    object,
    WorldAuthServer<unknown, unknown>
  >();
  private readonly nonceService: NonceService;
  private readonly tokens: TokenService<A, R>;
  private readonly nonceStore?: NonceStore;
  private readonly debug: boolean;
  private readonly siweClient?: Client;

  private constructor(config: WorldAuthServerConfig<A, R>) {
    const namespace = config.namespace ?? "world-auth";
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(namespace))
      throw new Error(
        "namespace must contain 1–64 letters, digits, underscores or hyphens",
      );
    const key =
      typeof config.secrets.jweSecret === "string"
        ? new TextEncoder().encode(config.secrets.jweSecret)
        : new Uint8Array(config.secrets.jweSecret);
    if (key.byteLength !== 32)
      throw new Error("jweSecret must contain exactly 32 bytes");
    for (const tokenConfig of [
      config.accessTokenConfig,
      config.refreshTokenConfig,
    ]) {
      if (
        !Number.isSafeInteger(tokenConfig.ttlMs) ||
        tokenConfig.ttlMs < 1000 ||
        !Number.isSafeInteger(Date.now() + tokenConfig.ttlMs)
      )
        throw new Error(
          "Token TTL must be a positive safe integer of at least 1000 milliseconds",
        );
    }
    if (!config.refreshTokenConfig.idField.trim())
      throw new Error("Refresh idField is required");
    if (
      typeof config.refreshTokenConfig.payloadSchema?.safeParse !== "function"
    )
      throw new Error("Refresh payloadSchema must be a Zod schema");
    if (
      config.accessTokenConfig.payloadSchema &&
      typeof config.accessTokenConfig.payloadSchema.safeParse !== "function"
    )
      throw new Error("Access payloadSchema must be a Zod schema");
    this.nonceService = new NonceService(config.secrets.nonceSecret);
    this.debug = config.debug ?? false;
    this.siweClient = config.siweClient;

    const redis = config.redisConfig
      ? new Redis({
          url: config.redisConfig.redisUrl,
          token: config.redisConfig.redisToken,
          automaticDeserialization: false,
        })
      : undefined;
    const groups = config.refreshTokenConfig.skipTokenGroupVerification
      ? undefined
      : (config.tokenGroupStore ??
        (redis
          ? {
              get: (key: string) => redis.get(key),
              incr: (key: string) => redis.incr(key),
            }
          : undefined));
    if (!groups && !config.refreshTokenConfig.skipTokenGroupVerification)
      throw new Error(
        "Configure Redis or tokenGroupStore, or explicitly disable refresh-token group verification",
      );
    this.tokens = new TokenService(
      key,
      namespace,
      { ...config.accessTokenConfig },
      { ...config.refreshTokenConfig },
      groups,
    );
    this.nonceStore =
      config.nonceStore ??
      (redis
        ? {
            consume: async (nonce, expiresAtMs) => {
              const ttl = expiresAtMs - Date.now();
              if (ttl <= 0) return false;
              const hash = createHash("sha256").update(nonce).digest("hex");
              return (
                (await redis.set(`${namespace}:nonce:${hash}`, "used", {
                  nx: true,
                  px: ttl,
                })) === "OK"
              );
            },
          }
        : undefined);
  }

  /** Cache by configuration object identity, never by schema field names or secret strings. */
  static async init<A = unknown, R = unknown>(
    config: WorldAuthServerConfig<A, R>,
  ): Promise<WorldAuthServer<A, R>> {
    const existing = this.instances.get(config);
    if (existing) return existing as WorldAuthServer<A, R>;
    const instance = new WorldAuthServer(config);
    this.instances.set(config, instance);
    return instance;
  }

  static async create<A = unknown, R = unknown>(
    config: WorldAuthServerConfig<A, R>,
  ): Promise<WorldAuthServer<A, R>> {
    return new WorldAuthServer(config);
  }

  async genNonce(ttlMs = 300_000) {
    return this.nonceService.genNonce(ttlMs);
  }
  verifyNonce(nonce: string) {
    return this.nonceService.verifyNonce(nonce);
  }

  /** Checks wallet proof and application context, then atomically consumes the challenge. */
  async verifySiwe(
    payload: unknown,
    nonce: string,
    options: SiweVerificationOptions,
  ): Promise<boolean> {
    try {
      if (
        !this.nonceStore ||
        !options ||
        !options.domain ||
        !options.uri ||
        typeof options.expectedNonce !== "string" ||
        typeof nonce !== "string"
      )
        return false;
      const expected = Buffer.from(options.expectedNonce);
      const received = Buffer.from(nonce);
      if (
        expected.length !== received.length ||
        !timingSafeEqual(expected, received)
      )
        return false;
      const challenge = this.verifyNonce(nonce);
      if (!challenge.valid || !challenge.expiresAtMs) return false;
      // MiniKit 2.0.3 logs RPC failures with signature details; use viem's quiet verifier.
      const { verifyWalletProof } = await import("./helpers/SiweService.js");
      const { MiniAppWalletAuthSuccessPayloadSchema } =
        await import("../../schemas/api/endpoints/ApiAuthCompleteSiwe/ApiAuthCompleteSiweReqSchema.js");
      const parsed = MiniAppWalletAuthSuccessPayloadSchema.safeParse(payload);
      if (!parsed.success) return false;
      if (
        !(await verifyWalletProof(parsed.data, nonce, options, this.siweClient))
      )
        return false;
      // Signature/RPC work can take time; recheck expiry before the store operation.
      if (Date.now() >= challenge.expiresAtMs) return false;
      return await this.nonceStore.consume(nonce, challenge.expiresAtMs);
    } catch {
      if (this.debug) console.debug("[world-auth] SIWE verification failed");
      return false;
    }
  }

  async genAccessToken(payload?: unknown) {
    const { token, expiresAt } = await this.tokens.genAccessToken(payload);
    return { accessToken: token, accessTokenExpiresAt: expiresAt };
  }
  verifyAccessToken(token: string) {
    return this.tokens.verifyAccessToken(token);
  }
  async genRefreshToken(payload: unknown) {
    const { token, expiresAt } = await this.tokens.genRefreshToken(payload);
    return { refreshToken: token, refreshTokenExpiresAt: expiresAt };
  }
  verifyRefreshToken(token: string) {
    return this.tokens.verifyRefreshToken(token);
  }
  rotateRefreshTokenGroup(token: string) {
    return this.tokens.rotateRefreshTokenGroup(token);
  }

  async setRefreshTokenCookie(
    token: string,
    expiresAt: number,
    callback: CookieWriter,
  ): Promise<void> {
    if (!Number.isSafeInteger(expiresAt))
      throw new Error("Cookie expiry must be a millisecond timestamp");
    await callback({
      name: "worldAuth_refreshToken",
      value: token,
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      path: "/",
      maxAge: Math.max(0, Math.floor((expiresAt - Date.now()) / 1000)),
    });
  }
  getRefreshTokenCookie(
    callback: (name: string) => string | null | undefined,
  ): string | null {
    return callback("worldAuth_refreshToken") || null;
  }
  async clearRefreshTokenCookie(callback: CookieClearer): Promise<void> {
    await callback("worldAuth_refreshToken", {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      path: "/",
      maxAge: 0,
    });
  }
}
