import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export interface NonceResult {
  nonce: string;
  expiresAtMs: number;
}

export interface NonceVerificationResult {
  valid: boolean;
  reason?: "invalid_format" | "invalid_signature" | "expired";
  expiresAtMs?: number;
}

/** Signed, expiring challenges. Session binding and consumption happen in verifySiwe. */
export class NonceService {
  constructor(private readonly secret: string) {
    if (typeof secret !== "string" || Buffer.byteLength(secret) < 32) {
      throw new Error("nonceSecret must contain at least 32 UTF-8 bytes");
    }
  }

  genNonce(ttlMs = 300_000): NonceResult {
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1000 || ttlMs > 900_000) {
      throw new Error("Nonce TTL must be between 1000 and 900000 milliseconds");
    }
    const expiresAtMs = Math.floor((Date.now() + ttlMs) / 1000) * 1000;
    const random = randomBytes(16).toString("hex");
    const expires = (expiresAtMs / 1000).toString(36).padStart(8, "0");
    return {
      nonce: random + expires + this.sign(random + expires),
      expiresAtMs,
    };
  }

  verifyNonce(nonce: string): NonceVerificationResult {
    if (
      typeof nonce !== "string" ||
      !/^[a-f0-9]{32}[a-z0-9]{8}[a-f0-9]{32}$/.test(nonce)
    ) {
      return { valid: false, reason: "invalid_format" };
    }
    const body = nonce.slice(0, 40);
    if (
      !timingSafeEqual(
        Buffer.from(this.sign(body), "hex"),
        Buffer.from(nonce.slice(40), "hex"),
      )
    ) {
      return { valid: false, reason: "invalid_signature" };
    }
    const expiresAtMs = Number.parseInt(nonce.slice(32, 40), 36) * 1000;
    if (Date.now() >= expiresAtMs) return { valid: false, reason: "expired" };
    return { valid: true, expiresAtMs };
  }

  private sign(value: string): string {
    return createHmac("sha256", this.secret)
      .update(value)
      .digest()
      .subarray(0, 16)
      .toString("hex");
  }
}
