import { z } from "zod";
import { ApiBaseResSchema } from "../../ApiBaseResSchema.js";
import { validators } from "../../../validators.js";

export const ApiAuthAccessTokenResSchema = ApiBaseResSchema.extend({
  accessToken: z.string(),
  accessTokenExpiresAt: validators.timestampMs(),
});
