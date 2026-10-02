import { z } from "zod";
export const validators = {
  timestampMs: () => z.number().int().nonnegative(),
  ethereumAddress: () => z.string().regex(/^0x[a-fA-F0-9]{40}$/),
};
