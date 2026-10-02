import { z } from "zod";
import { ApiBaseResSchema } from "../../ApiBaseResSchema.js";
import { validators } from "../../../validators.js";

export const ApiAuthAppSessionResSchema = ApiBaseResSchema.extend({
  accessToken: z.string(),
  accessTokenExpiresAt: validators.timestampMs(),
  walletAddress: validators.ethereumAddress(),
  userId: z.string(),
});
