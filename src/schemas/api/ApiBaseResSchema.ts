import { z } from "zod";

export enum HttpStatusCodes {
  BAD_REQUEST = 400,
  UNAUTHORIZED = 401,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  INTERNAL_SERVER_ERROR = 500,
  UNKNOWN = 500,
  OK = 200,
}

export enum ApiStatus {
  SUCCESS = "SUCCESS",
  ERROR = "ERROR",
}

export enum ApiResCodes {
  ERROR_UNKNOWN,
  ERROR_INVALID_VISITOR_ID_OR_CLIENT_IP,
  ERROR_NOT_ALL_ARGUMENTS_PROVIDED,
  ERROR_INVALID_NONCE,
  ERROR_USER_NOT_FOUND,
  ERROR_ACCESS_TOKEN_GENERATION_FAILED,
  ERROR_REFRESH_TOKEN_GENERATION_FAILED,
  ERROR_RATE_LIMIT_EXCEEDED,
  ERROR_INVALID_SIWE_MESSAGE_OR_SIGNATURE,
  ERROR_MISSING_REFRESH_TOKEN,
  ERROR_INVALID_REFRESH_TOKEN,
  ERROR_MISSING_ACCESS_TOKEN,
  ERROR_INVALID_ACCESS_TOKEN,
  ERROR_WORLD_USERNAME_QUERY_FAILED,
  ERROR_INVALID_PAYLOAD,
  ERROR_MISSING_ENV_VAR,
  ERROR_ACCESS_DENIED,
  ERROR_SERVER_ERROR,
  ERROR_INTERNAL_SERVER_ERROR,
  ERROR_GENERIC,
  SUCCESS_REQUEST_COMPLETED,
}

export const HttpStatusCodesSchema = z.enum(HttpStatusCodes);
export const ApiStatusSchema = z.enum(ApiStatus);
export const ApiResCodesSchema = z.enum(ApiResCodes);

export const ApiBaseResSchema = z.object({
  status: ApiStatusSchema,
  statusCode: HttpStatusCodesSchema,
  respCode: ApiResCodesSchema,
  version: z.string(),
  message: z.string().optional(),
});
