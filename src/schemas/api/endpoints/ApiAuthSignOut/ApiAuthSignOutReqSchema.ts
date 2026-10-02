import { z } from "zod";

export const ApiAuthSignOutReqSchema = z.object({
  signAllOut: z.boolean(),
});
