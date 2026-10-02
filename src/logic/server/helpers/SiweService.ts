import { createPublicClient, http, isHex } from "viem";
import type { Client, Address } from "viem";
import { worldchain } from "viem/chains";
import { parseSiweMessage, validateSiweMessage } from "viem/siwe";
import { verifyMessage } from "viem/actions";
import type { SiweVerificationOptions } from "../WorldAuthServer.js";

interface WalletProof {
  address: string;
  message: string;
  signature: string;
}

/** Validate application context before signature/RPC work. The verifier never prints its inputs. */
export async function verifyWalletProof(
  proof: WalletProof,
  nonce: string,
  options: SiweVerificationOptions,
  suppliedClient?: Client,
): Promise<boolean> {
  const message = parseSiweMessage(proof.message);
  if (
    message.version !== "1" ||
    !message.issuedAt ||
    !Number.isFinite(message.issuedAt.getTime()) ||
    message.issuedAt.getTime() > Date.now() + 30_000 ||
    message.uri !== options.uri ||
    message.chainId !== (options.chainId ?? 480) ||
    (options.statement !== undefined &&
      message.statement !== options.statement) ||
    (options.requestId !== undefined &&
      message.requestId !== options.requestId) ||
    !validateSiweMessage({
      message,
      domain: options.domain,
      nonce,
      address: proof.address as Address,
      time: new Date(),
    }) ||
    !isHex(proof.signature, { strict: true })
  )
    return false;
  const client =
    suppliedClient ??
    createPublicClient({
      chain: worldchain,
      transport: http(undefined, { timeout: 10_000, retryCount: 0 }),
    });
  if (client.chain?.id !== (options.chainId ?? 480)) return false;
  return verifyMessage(client, {
    address: proof.address as Address,
    message: proof.message,
    signature: proof.signature,
    mode: "eoa",
  });
}
