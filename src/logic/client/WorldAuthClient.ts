import { z } from "zod";
import {
  ApiAuthNonceResSchema,
  ApiAuthCompleteSiweReqSchema,
  ApiAuthCompleteSiweResSchema,
  ApiAuthAppSessionReqSchema,
  ApiAuthAppSessionResSchema,
  ApiAuthAccessTokenResSchema,
  ApiAuthSignOutReqSchema,
  ApiAuthSignOutResSchema,
  ApiAuthClearCookiesResSchema,
} from "../../schemas.js";
import { callBackend } from "./helpers/callBackend.js";
import type { EndpointSchema, HttpMethod } from "./helpers/callBackend.js";

const paths = {
  nonce: "/api/auth/nonce",
  completeSiwe: "/api/auth/complete-siwe",
  appSession: "/api/auth/app-session",
  accessToken: "/api/auth/access-token",
  signOut: "/api/auth/sign-out",
  clearCookies: "/api/auth/clear-cookies",
} as const;
type Endpoint = keyof typeof paths;
const defaults: Record<Endpoint, EndpointSchema> = {
  nonce: { req: null, res: ApiAuthNonceResSchema },
  completeSiwe: {
    req: ApiAuthCompleteSiweReqSchema,
    res: ApiAuthCompleteSiweResSchema,
  },
  appSession: {
    req: ApiAuthAppSessionReqSchema,
    res: ApiAuthAppSessionResSchema,
  },
  accessToken: { req: null, res: ApiAuthAccessTokenResSchema },
  signOut: { req: ApiAuthSignOutReqSchema, res: ApiAuthSignOutResSchema },
  clearCookies: { req: null, res: ApiAuthClearCookiesResSchema },
};
const accessFields = z.object({
  accessToken: z.string().min(1),
  accessTokenExpiresAt: z.number().int().nonnegative(),
});
const authFields = accessFields.extend({
  refreshTokenExpiresAt: z.number().int().nonnegative(),
});
type AccessFields = z.infer<typeof accessFields>;
type AuthFields = z.infer<typeof authFields>;
export type TokenStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;
export interface WalletAuthOptions {
  requestId?: string;
  expirationTime?: Date;
  notBefore?: Date;
  statement?: string;
}
export interface MiniKitAdapter {
  walletAuth(options: WalletAuthOptions & { nonce: string }): Promise<unknown>;
}
export interface WorldAuthClientConfigInput {
  baseUrl: string;
  miniKit: MiniKitAdapter;
  urlPaths?: Partial<Record<Endpoint, string>>;
  defaultStatement?: string;
  customSchemas?: Partial<Record<Endpoint, Partial<EndpointSchema> | null>>;
  /** Memory-only by default. Opt in to browser storage only after assessing XSS exposure. */
  storage?: TokenStorage | null;
  storageKey?: string;
  requestTimeoutMs?: number;
  debug?: boolean;
}

/** One application per browser realm. The singleton is never shared with server verification. */
export class WorldAuthClient {
  private static instance: WorldAuthClient | null = null;
  private readonly urlPaths: Record<Endpoint, string>;
  private readonly schemas: Record<Endpoint, EndpointSchema>;
  private tokens: Partial<AuthFields> = {};
  private generation = 0;
  private pendingClosures = 0;
  private refreshPromise?: Promise<z.infer<typeof ApiAuthAccessTokenResSchema>>;
  private readonly storageKey: string;

  private constructor(private readonly config: WorldAuthClientConfigInput) {
    const url = new URL(config.baseUrl);
    if (
      !["https:", "http:"].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    )
      throw new Error(
        "baseUrl must be an HTTP(S) URL without credentials, a query or a fragment",
      );
    if (typeof config.miniKit?.walletAuth !== "function")
      throw new Error("miniKit.walletAuth is required");
    const timeout = config.requestTimeoutMs ?? 15_000;
    if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 120_000)
      throw new Error("requestTimeoutMs must be between 1 and 120000");
    this.urlPaths = { ...paths, ...config.urlPaths };
    this.schemas = { ...defaults };
    for (const endpoint of Object.keys(paths) as Endpoint[]) {
      const override = config.customSchemas?.[endpoint];
      const schema = { ...defaults[endpoint], ...override };
      if (
        typeof schema.res?.safeParse !== "function" ||
        (schema.req !== null && typeof schema.req?.safeParse !== "function")
      )
        throw new Error("Endpoint schemas must be Zod schemas");
      if (!this.urlPaths[endpoint].startsWith("/"))
        throw new Error("Endpoint paths must begin with /");
      this.schemas[endpoint] = schema;
    }
    this.storageKey = config.storageKey ?? "worldAuth.tokens";
    this.restore();
  }

  static init(config: WorldAuthClientConfigInput): WorldAuthClient {
    const next = new WorldAuthClient({
      ...config,
      baseUrl: config.baseUrl.replace(/\/+$/, ""),
    });
    if (this.instance) this.instance.generation++;
    this.instance = next;
    return next;
  }
  static isInitialized(): boolean {
    return this.instance !== null;
  }
  static reset(): void {
    if (this.instance) this.instance.generation++;
    this.instance = null;
  }
  private static get(): WorldAuthClient {
    if (!this.instance)
      throw new Error(
        "WorldAuthClient not initialized. Call WorldAuthClient.init() first.",
      );
    return this.instance;
  }
  static get isAuthenticated(): boolean {
    const { tokens } = this.get();
    return (
      !!tokens.accessToken && (tokens.accessTokenExpiresAt ?? 0) > Date.now()
    );
  }
  static get expectedToBeAuthenticated(): boolean {
    return (this.get().tokens.refreshTokenExpiresAt ?? 0) > Date.now();
  }
  private assertCurrent(generation: number): void {
    if (WorldAuthClient.instance !== this || generation !== this.generation)
      throw new Error("Authentication operation superseded");
    if (this.pendingClosures > 0)
      throw new Error("Session sign-out is in progress");
  }
  private call<T>(
    endpoint: Endpoint,
    method: HttpMethod,
    data?: unknown,
    headers: Record<string, string> = {},
    schemas = this.schemas[endpoint],
  ): Promise<T> {
    return callBackend<T>(
      this.config.baseUrl,
      this.urlPaths[endpoint],
      method,
      schemas,
      data,
      headers,
      this.config.debug,
      this.config.requestTimeoutMs,
    );
  }
  private persist(): void {
    try {
      this.config.storage?.setItem(
        this.storageKey,
        JSON.stringify(this.tokens),
      );
    } catch {
      /* Storage may be unavailable in embedded browsers. Memory remains authoritative. */
    }
  }
  private clear(): void {
    this.generation++;
    this.tokens = {};
    this.refreshPromise = undefined;
    try {
      this.config.storage?.removeItem(this.storageKey);
    } catch {
      /* Logout must clear memory even if storage fails. */
    }
  }
  private restore(): void {
    try {
      const raw = this.config.storage?.getItem(this.storageKey);
      if (!raw) return;
      const parsed = authFields.partial().safeParse(JSON.parse(raw));
      if (!parsed.success) throw new Error("Invalid cache");
      const value = parsed.data;
      if (value.accessToken && (value.accessTokenExpiresAt ?? 0) > Date.now())
        this.tokens = {
          accessToken: value.accessToken,
          accessTokenExpiresAt: value.accessTokenExpiresAt,
        };
      if ((value.refreshTokenExpiresAt ?? 0) > Date.now())
        this.tokens.refreshTokenExpiresAt = value.refreshTokenExpiresAt;
      this.persist();
    } catch {
      this.clear();
    }
  }

  static getNonce(): Promise<z.infer<typeof ApiAuthNonceResSchema>> {
    const client = this.get();
    client.assertCurrent(client.generation);
    return client.call("nonce", "GET");
  }
  static commitAuth(fields: AuthFields): void {
    const client = this.get();
    client.assertCurrent(client.generation);
    client.tokens = authFields.parse(fields);
    client.persist();
  }
  static commitAccess(fields: AccessFields): void {
    const client = this.get();
    client.assertCurrent(client.generation);
    client.tokens = { ...client.tokens, ...accessFields.parse(fields) };
    client.persist();
  }

  static completeSiwe(
    payload: z.input<typeof ApiAuthCompleteSiweReqSchema>,
    reqSchema?: undefined,
    resSchema?: undefined,
    headers?: Record<string, string>,
    opts?: { deferCommit?: boolean },
  ): Promise<z.output<typeof ApiAuthCompleteSiweResSchema>>;
  static completeSiwe<
    TReq extends z.ZodType = typeof ApiAuthCompleteSiweReqSchema,
    TRes extends z.ZodType = typeof ApiAuthCompleteSiweResSchema,
  >(
    payload: z.input<TReq>,
    reqSchema?: TReq,
    resSchema?: TRes,
    headers?: Record<string, string>,
    opts?: { deferCommit?: boolean },
  ): Promise<z.output<TRes>>;
  static async completeSiwe<
    TReq extends z.ZodType = typeof ApiAuthCompleteSiweReqSchema,
    TRes extends z.ZodType = typeof ApiAuthCompleteSiweResSchema,
  >(
    payload: z.input<TReq>,
    reqSchema?: TReq,
    resSchema?: TRes,
    headers: Record<string, string> = {},
    opts?: { deferCommit?: boolean },
  ): Promise<z.output<TRes>> {
    const client = this.get();
    const generation = client.generation;
    client.assertCurrent(generation);
    const response = await client.call<z.output<TRes>>(
      "completeSiwe",
      "POST",
      payload,
      headers,
      {
        req: reqSchema ?? client.schemas.completeSiwe.req,
        res: resSchema ?? client.schemas.completeSiwe.res,
      },
    );
    client.assertCurrent(generation);
    if (!opts?.deferCommit) {
      const fields = accessFields.safeParse(response);
      if (fields.success) this.commitAccess(fields.data);
      const refresh = z
        .object({ refreshTokenExpiresAt: z.number().int().nonnegative() })
        .safeParse(response);
      if (refresh.success) {
        client.tokens.refreshTokenExpiresAt =
          refresh.data.refreshTokenExpiresAt;
        client.persist();
      }
    }
    return response;
  }

  static async getAppSession<
    TReq extends z.ZodType = typeof ApiAuthAppSessionReqSchema,
    TRes extends z.ZodType = typeof ApiAuthAppSessionResSchema,
  >(
    payload: z.input<TReq>,
    reqSchema?: TReq,
    resSchema?: TRes,
    headers: Record<string, string> = {},
  ): Promise<z.output<TRes>> {
    const client = this.get();
    const generation = client.generation;
    client.assertCurrent(generation);
    const response = await client.call<z.output<TRes>>(
      "appSession",
      "POST",
      payload,
      headers,
      {
        req: reqSchema ?? client.schemas.appSession.req,
        res: resSchema ?? client.schemas.appSession.res,
      },
    );
    client.assertCurrent(generation);
    const fields = accessFields.safeParse(response);
    if (fields.success) this.commitAccess(fields.data);
    return response;
  }

  static async getAccessToken(): Promise<
    z.infer<typeof ApiAuthAccessTokenResSchema>
  > {
    const client = this.get();
    client.assertCurrent(client.generation);
    if (client.refreshPromise) return client.refreshPromise;
    const generation = client.generation;
    const pending = client
      .call<z.infer<typeof ApiAuthAccessTokenResSchema>>("accessToken", "POST")
      .then((response) => {
        client.assertCurrent(generation);
        this.commitAccess(response);
        return response;
      });
    client.refreshPromise = pending;
    try {
      return await pending;
    } finally {
      if (client.refreshPromise === pending) client.refreshPromise = undefined;
    }
  }
  static async getAccessTokenSilently(): Promise<AccessFields> {
    const client = this.get();
    if (
      client.tokens.accessToken &&
      (client.tokens.accessTokenExpiresAt ?? 0) > Date.now()
    )
      return accessFields.parse(client.tokens);
    delete client.tokens.accessToken;
    delete client.tokens.accessTokenExpiresAt;
    client.persist();
    return this.getAccessToken();
  }
  static async signOut(
    options: z.input<typeof ApiAuthSignOutReqSchema> = { signAllOut: true },
  ): Promise<z.infer<typeof ApiAuthSignOutResSchema>> {
    const client = this.get();
    client.clear();
    client.pendingClosures++;
    try {
      return await client.call("signOut", "POST", options);
    } finally {
      client.pendingClosures--;
    }
  }
  static async clearCookies(): Promise<
    z.infer<typeof ApiAuthClearCookiesResSchema>
  > {
    const client = this.get();
    client.clear();
    client.pendingClosures++;
    try {
      return await client.call("clearCookies", "POST");
    } finally {
      client.pendingClosures--;
    }
  }
  static async walletAuth(
    options: WalletAuthOptions = {},
  ): Promise<z.infer<typeof ApiAuthCompleteSiweResSchema>> {
    const client = this.get();
    const generation = client.generation;
    const challenge = await this.getNonce();
    client.assertCurrent(generation);
    const result = await client.config.miniKit.walletAuth({
      nonce: challenge.nonce,
      requestId: options.requestId ?? crypto.randomUUID(),
      expirationTime:
        options.expirationTime ?? new Date(challenge.nonceExpiresAt),
      ...options,
      statement:
        options.statement ??
        client.config.defaultStatement ??
        "Sign in to continue.",
    });
    client.assertCurrent(generation);
    const command = z
      .object({
        executedWith: z.enum(["minikit", "wagmi"]),
        data: z.object({
          address: z.string(),
          message: z.string(),
          signature: z.string(),
        }),
      })
      .safeParse(result);
    if (!command.success)
      throw new Error(
        "Wallet authentication command did not return a successful proof",
      );
    return this.completeSiwe({
      nonce: challenge.nonce,
      payload: { ...command.data.data, status: "success", version: 1 },
    });
  }
}
