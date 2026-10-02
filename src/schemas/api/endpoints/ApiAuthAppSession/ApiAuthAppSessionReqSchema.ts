import { z } from "zod";
/** This endpoint requires an application-defined privileged authorization policy. */
export const ApiAuthAppSessionReqSchema = z.object({
  userId: z.string().min(1),
});
