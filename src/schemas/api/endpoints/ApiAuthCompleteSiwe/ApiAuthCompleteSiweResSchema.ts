import { z } from "zod";
import { ApiBaseResSchema } from "../../ApiBaseResSchema.js";
import { validators } from "../../../validators.js";

export const ApiAuthCompleteSiweResSchema = ApiBaseResSchema.extend({
  refreshTokenExpiresAt: validators.timestampMs(),
  accessToken: z.string(),
  accessTokenExpiresAt: validators.timestampMs(),
  walletAddress: validators.ethereumAddress(),
  userId: z.string(),
});
