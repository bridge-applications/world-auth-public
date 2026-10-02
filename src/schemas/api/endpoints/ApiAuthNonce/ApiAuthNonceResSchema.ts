import { z } from "zod";
import { ApiBaseResSchema } from "../../ApiBaseResSchema.js";
import { validators } from "../../../validators.js";

export const ApiAuthNonceResSchema = ApiBaseResSchema.extend({
  nonce: z.string(),
  nonceExpiresAt: validators.timestampMs(),
});
