import { z } from "zod";
import { ApiBaseResSchema } from "../../ApiBaseResSchema.js";

export const ApiAuthClearCookiesResSchema = ApiBaseResSchema.extend({
  success: z.boolean(),
});
