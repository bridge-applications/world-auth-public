import { z } from "zod";
import { validators } from "../../../validators.js";

export const MiniAppWalletAuthSuccessPayloadSchema = z.object({
  status: z.literal("success"),
  message: z.string().min(1).max(8192),
  signature: z.string().min(1).max(16384),
  address: validators.ethereumAddress(),
  version: z.number().int().positive(),
});

export const ApiAuthCompleteSiweReqSchema = z.object({
  nonce: z.string().regex(/^[a-zA-Z0-9]{8,128}$/),
  payload: MiniAppWalletAuthSuccessPayloadSchema,
});
