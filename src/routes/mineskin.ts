import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { URL } from "node:url";
import { createRoute, OpenAPIHono, z } from "@hono/zod-openapi";
import { FormData as UndiciFormData, fetch as undiciFetch } from "undici";

const MINESKIN_BASE_URL = "https://api.mineskin.org/v2";
const MINESKIN_USER_AGENT = "Axolotl-MineSkin-Proxy/1.0";
const ENCRYPTED_URL_SCHEME = "skinsrestorer-axolotl://";
const DEFAULT_POLL_INTERVAL_MS = 1_000;
const MAX_POLL_DURATION_MS = 5 * 60 * 1_000;
const CAPE_CACHE_TTL_MS = 5 * 60 * 1_000;

function getAesSecretKey(): Buffer {
  const key = process.env.AES_SECRET_KEY;
  if (!key) {
    throw new ConfigurationError(
      "AES_SECRET_KEY environment variable is not set",
    );
  }
  // Use SHA-256 to derive a 32-byte key
  return createHash("sha256").update(key).digest();
}

function encryptUrl(url: string): string {
  const key = getAesSecretKey();
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(url, "utf8", "base64");
  encrypted += cipher.final("base64");
  const combined = Buffer.concat([iv, Buffer.from(encrypted, "base64")]);
  return `${ENCRYPTED_URL_SCHEME}${combined.toString("base64")}`;
}

function decryptUrl(encryptedUrl: string): string {
  if (!encryptedUrl.startsWith(ENCRYPTED_URL_SCHEME)) {
    throw new Error("Invalid encrypted URL format");
  }
  const key = getAesSecretKey();
  const combined = Buffer.from(
    encryptedUrl.slice(ENCRYPTED_URL_SCHEME.length),
    "base64",
  );
  const iv = combined.subarray(0, 16);
  const encrypted = combined.subarray(16);
  const decipher = createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString("utf8");
}

function encryptMineSkinUrls(obj: unknown): unknown {
  if (typeof obj === "string") {
    // Check if it's a URL (basic check)
    if (obj.startsWith("http://") || obj.startsWith("https://")) {
      return encryptUrl(obj);
    }
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(encryptMineSkinUrls);
  }
  if (obj && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = encryptMineSkinUrls(value);
    }
    return result;
  }
  return obj;
}

function sanitizeMineSkinJobResponse(
  data: MineSkinJobSuccessResponse,
): MineSkinSanitizedResponse {
  let skin: MineSkinSanitizedResponse["skin"] = null;

  const skinData = data.skin;
  if (
    skinData &&
    typeof skinData === "object" &&
    "uuid" in skinData &&
    typeof skinData.uuid === "string"
  ) {
    const encryptedUrl = encryptUrl(`https://minesk.in/${skinData.uuid}`);
    skin = { url: encryptedUrl };
  }

  return {
    success: true,
    skin,
    warnings: data.warnings ?? [],
    messages: data.messages ?? [],
  };
}

const jobStatusSchema = z.enum([
  "unknown",
  "waiting",
  "active",
  "processing",
  "failed",
  "completed",
]);

const mineSkinErrorSchema = z.object({
  code: z.string().optional(),
  message: z.string().optional(),
});

const mineSkinJobDetailsSchema = z
  .object({
    id: z.string(),
    status: jobStatusSchema,
    result: z.string().nullish(),
  })
  .passthrough();

const mineSkinValueAndSignatureSchema = z.object({
  value: z.string(),
  signature: z.string(),
});

const mineSkinSkinHashesSchema = z.object({
  skin: z.string(),
  cape: z.string().optional(),
});

const mineSkinSkinUrlsSchema = z.object({
  skin: z.string(),
  cape: z.string().optional(),
});

const mineSkinSkinTextureSchema = z
  .object({
    data: mineSkinValueAndSignatureSchema,
    hash: mineSkinSkinHashesSchema.nullish(),
    url: mineSkinSkinUrlsSchema.nullish(),
  })
  .passthrough();

const mineSkinGeneratorInfoSchema = z
  .object({
    version: z.string(),
    timestamp: z.number(),
    duration: z.number(),
    account: z.string(),
    server: z.string(),
  })
  .passthrough();

const mineSkinSkinSchema = z
  .object({
    uuid: z.string(),
    name: z.string().nullable(),
    visibility: z.enum(["public", "unlisted", "private"]),
    variant: z.enum(["classic", "slim", "unknown"]),
    texture: mineSkinSkinTextureSchema,
    generator: mineSkinGeneratorInfoSchema,
    views: z.number(),
    duplicate: z.boolean(),
  })
  .passthrough();

const mineSkinDelayInfoSchema = z
  .object({
    millis: z.number(),
    seconds: z.number().optional(),
  })
  .passthrough();

const mineSkinNextRequestSchema = z
  .object({
    absolute: z.number(),
    relative: z.number(),
  })
  .passthrough();

const mineSkinLimitInfoSchema = z
  .object({
    limit: z.number(),
    remaining: z.number(),
    reset: z.number().optional(),
  })
  .passthrough();

const mineSkinRateLimitInfoSchema = z
  .object({
    next: mineSkinNextRequestSchema,
    delay: mineSkinDelayInfoSchema,
    limit: mineSkinLimitInfoSchema.optional(),
  })
  .passthrough();

const mineSkinCreditsUsageSchema = z
  .object({
    used: z.number(),
    remaining: z.number(),
  })
  .passthrough();

const mineSkinMeteredUsageSchema = z
  .object({
    used: z.number(),
  })
  .passthrough();

const mineSkinUsageInfoSchema = z
  .object({
    credits: mineSkinCreditsUsageSchema.optional(),
    metered: mineSkinMeteredUsageSchema.optional(),
  })
  .passthrough();

const mineSkinSkinResultSchema = z
  .union([mineSkinSkinSchema, z.literal(false)])
  .nullish();

const mineSkinJobSuccessSchema = z
  .object({
    success: z.literal(true),
    job: mineSkinJobDetailsSchema,
    skin: mineSkinSkinResultSchema,
    rateLimit: mineSkinRateLimitInfoSchema.nullish(),
    usage: mineSkinUsageInfoSchema.nullish(),
    errors: z.array(mineSkinErrorSchema).optional(),
    warnings: z.array(mineSkinErrorSchema).optional(),
    messages: z.array(mineSkinErrorSchema).optional(),
    links: z
      .object({
        self: z.string().optional(),
      })
      .catchall(z.unknown())
      .optional(),
  })
  .passthrough();

const mineSkinSanitizedSkinSchema = z.object({
  url: z.string(),
});

const mineSkinSanitizedResponseSchema = z.object({
  success: z.literal(true),
  skin: mineSkinSanitizedSkinSchema.nullable(),
  warnings: z.array(mineSkinErrorSchema).default([]),
  messages: z.array(mineSkinErrorSchema).default([]),
});

const mineSkinCapeSchema = z.object({
  uuid: z.string(),
  alias: z.string(),
  url: z.string().url(),
});

type MineSkinError = z.infer<typeof mineSkinErrorSchema>;
type MineSkinJobDetails = z.infer<typeof mineSkinJobDetailsSchema>;
type MineSkinJobSuccessResponse = z.infer<typeof mineSkinJobSuccessSchema>;
type MineSkinSanitizedResponse = z.infer<
  typeof mineSkinSanitizedResponseSchema
>;
type MineSkinCape = z.infer<typeof mineSkinCapeSchema>;

type MineSkinRateLimitInfo = z.infer<typeof mineSkinRateLimitInfoSchema>;
type MineSkinUsageInfo = z.infer<typeof mineSkinUsageInfoSchema>;

type MineSkinGenericResponse = {
  success?: boolean | undefined;
  errors?: MineSkinError[] | undefined;
  warnings?: MineSkinError[] | undefined;
  messages?: MineSkinError[] | undefined;
  rateLimit?: MineSkinRateLimitInfo | null | undefined;
  usage?: MineSkinUsageInfo | null | undefined;
};

type MineSkinEnqueueResponse = MineSkinGenericResponse & {
  job?: MineSkinJobDetails;
  skin?: MineSkinJobSuccessResponse["skin"];
};

type MineSkinJobResponse =
  | MineSkinJobSuccessResponse
  | (MineSkinGenericResponse & {
      job?: MineSkinJobDetails;
      skin?: MineSkinJobSuccessResponse["skin"];
    });

type MineSkinCapeResponse = MineSkinGenericResponse & {
  capes?: (MineSkinCape & { supported?: boolean })[];
};

type MineSkinMeResponse = MineSkinGenericResponse & {
  user?: string;
  grants?: Record<string, unknown>;
};

class ConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigurationError";
  }
}

class UpstreamError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "UpstreamError";
    this.status = status;
  }
}

function logMineSkinParsingError(
  context: string,
  response: unknown,
  error: unknown,
): void {
  const payload: Record<string, unknown> = { response };

  if (error instanceof Error) {
    payload.error = {
      name: error.name,
      message: error.message,
      stack: error.stack,
    };
  } else if (error !== undefined) {
    payload.error = error;
  }

  console.error(`[MineSkin] Failed to parse ${context}`, payload);
}

const uploadNameSchema = z.string().trim().min(1).max(64).optional();

const uploadFormSchema = z.object({
  variant: z.enum(["classic", "slim"]),
  name: uploadNameSchema,
  capeUuid: z.string().uuid(),
});

const uploadQuerySchema = z.object({
  waitMs: z.coerce.number().int().min(250).max(10_000).optional().openapi({
    description: "Polling interval in milliseconds.",
    example: 1000,
  }),
});

const capeSupportResponseSchema = z.object({
  hasCapeGrant: z.boolean(),
  capes: z.array(mineSkinCapeSchema),
});

type UploadFormData = z.infer<typeof uploadFormSchema>;

let cachedSupportedCapes: { data: MineSkinCape[]; fetchedAt: number } | null =
  null;

export const mineskinRouter = new OpenAPIHono();

function resolveAuthorizationHeader(): string {
  const rawKey = process.env.MINESKIN_API_KEY;
  if (!rawKey) {
    throw new ConfigurationError("MineSkin API key is not configured");
  }

  const trimmed = rawKey.trim();
  if (!trimmed) {
    throw new ConfigurationError("MineSkin API key is empty");
  }

  return trimmed.startsWith("Bearer ") ? trimmed : `Bearer ${trimmed}`;
}

function createMineSkinHeaders(): Record<string, string> {
  return {
    "User-Agent": MINESKIN_USER_AGENT,
    Authorization: resolveAuthorizationHeader(),
  };
}

function sanitizeStatus(status: number): number {
  if (Number.isInteger(status) && status >= 100 && status <= 599) {
    return status;
  }

  return 502;
}

function normalizeStatus(
  status: number,
  allowed: number[],
  fallback: number,
): number {
  const sanitized = sanitizeStatus(status);
  const safeFallback = sanitizeStatus(fallback);
  return allowed.map(sanitizeStatus).includes(sanitized)
    ? sanitized
    : safeFallback;
}

function getFirstMineSkinMessage(items?: MineSkinError[]): string | undefined {
  return items?.find((item) => item?.message)?.message;
}

function getMineSkinErrorMessage(response: MineSkinGenericResponse): string {
  return (
    getFirstMineSkinMessage(response.errors) ??
    getFirstMineSkinMessage(response.warnings) ??
    getFirstMineSkinMessage(response.messages) ??
    "MineSkin request failed"
  );
}

function ensureHttpsTextureUrl(url?: string | null): string | undefined {
  if (!url) {
    return undefined;
  }

  try {
    const parsed = new URL(url);
    if (parsed.protocol === "http:") {
      parsed.protocol = "https:";
    }
    return parsed.toString();
  } catch (error) {
    console.warn("Failed to normalise cape URL", error);
    return url;
  }
}

function isFileLike(value: unknown): value is Blob {
  if (!value || typeof value === "string") {
    return false;
  }

  return typeof (value as Blob).arrayBuffer === "function";
}

async function fetchMineSkinJob(
  jobId: string,
): Promise<MineSkinJobSuccessResponse> {
  const response = await undiciFetch(`${MINESKIN_BASE_URL}/queue/${jobId}`, {
    headers: createMineSkinHeaders(),
  });

  const data = (await response.json()) as MineSkinJobResponse;

  if (!response.ok || data.success === false) {
    const status = response.ok ? 502 : response.status;
    throw new UpstreamError(status, getMineSkinErrorMessage(data));
  }

  try {
    const parsed = mineSkinJobSuccessSchema.parse(data);
    return parsed;
  } catch (error) {
    logMineSkinParsingError("MineSkin job response", data, error);
    if (error instanceof z.ZodError) {
      const details = error.issues
        .map((issue) => {
          const path = issue.path.join(".");
          return path ? `${path}: ${issue.message}` : issue.message;
        })
        .filter((detail): detail is string => Boolean(detail))
        .join("; ");

      const suffix = details ? `: ${details}` : "";
      throw new UpstreamError(502, `Unexpected MineSkin job response${suffix}`);
    }

    throw new UpstreamError(502, "Unexpected MineSkin job response");
  }
}

async function pollMineSkinJob(
  jobId: string,
  waitMs: number,
): Promise<MineSkinSanitizedResponse> {
  const maxAttempts = Math.max(1, Math.ceil(MAX_POLL_DURATION_MS / waitMs));

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const jobData = await fetchMineSkinJob(jobId);
    const { status } = jobData.job;

    if (status === "completed") {
      if (!jobData.skin) {
        throw new UpstreamError(
          502,
          "MineSkin job completed but no skin data provided",
        );
      }
      return sanitizeMineSkinJobResponse(jobData);
    }

    if (status === "failed") {
      throw new UpstreamError(502, "MineSkin job failed to complete");
    }

    if (attempt < maxAttempts - 1) {
      await delay(waitMs);
    }
  }

  throw new UpstreamError(504, "Timed out waiting for MineSkin job to finish");
}

async function enqueueMineSkinJob(
  formData: UndiciFormData,
): Promise<MineSkinJobDetails> {
  const response = await undiciFetch(`${MINESKIN_BASE_URL}/queue`, {
    method: "POST",
    headers: createMineSkinHeaders(),
    body: formData,
  });

  const data = (await response.json()) as MineSkinEnqueueResponse;

  if (!response.ok || data.success === false || !data.job) {
    const status = response.ok ? 502 : response.status;
    throw new UpstreamError(status, getMineSkinErrorMessage(data));
  }

  try {
    return mineSkinJobDetailsSchema.parse(data.job);
  } catch (error) {
    logMineSkinParsingError("MineSkin job enqueue response", data, error);
    throw new UpstreamError(502, "Unexpected MineSkin job response");
  }
}

async function fetchMineSkinSupportedCapes(): Promise<MineSkinCape[]> {
  const response = await undiciFetch(`${MINESKIN_BASE_URL}/capes`, {
    headers: createMineSkinHeaders(),
  });

  const data = (await response.json()) as MineSkinCapeResponse;

  if (!response.ok || data.success === false) {
    const status = response.ok ? 502 : response.status;
    throw new UpstreamError(status, getMineSkinErrorMessage(data));
  }

  const capes = (data.capes ?? [])
    .filter((cape) => cape.supported)
    .map((cape) => ({
      uuid: cape.uuid,
      alias: cape.alias,
      url: ensureHttpsTextureUrl(cape.url) ?? cape.url,
    }));

  try {
    const parsed = z.array(mineSkinCapeSchema).parse(capes);
    return encryptMineSkinUrls(parsed) as MineSkinCape[];
  } catch (error) {
    logMineSkinParsingError("MineSkin cape response", capes, error);
    throw new UpstreamError(502, "Unexpected MineSkin cape response");
  }
}

async function fetchMineSkinCapeGrant(): Promise<boolean> {
  const response = await undiciFetch(`${MINESKIN_BASE_URL}/me`, {
    headers: createMineSkinHeaders(),
  });

  const data = (await response.json()) as MineSkinMeResponse;

  if (!response.ok || data.success === false) {
    const status = response.ok ? 502 : response.status;
    throw new UpstreamError(status, getMineSkinErrorMessage(data));
  }

  return Boolean(data.grants?.capes);
}

async function getSupportedCapes(): Promise<MineSkinCape[]> {
  const now = Date.now();
  if (
    cachedSupportedCapes &&
    now - cachedSupportedCapes.fetchedAt < CAPE_CACHE_TTL_MS
  ) {
    return cachedSupportedCapes.data;
  }

  const capes = await fetchMineSkinSupportedCapes();
  cachedSupportedCapes = { data: capes, fetchedAt: now };
  return capes;
}

function parseUploadForm(formData: FormData): UploadFormData {
  const variant = formData.get("variant");
  const name = formData.get("name");
  const capeUuid = formData.get("capeUuid") ?? formData.get("cape");

  const parsed = uploadFormSchema.safeParse({
    variant: typeof variant === "string" ? variant : undefined,
    name: typeof name === "string" ? name : undefined,
    capeUuid: typeof capeUuid === "string" ? capeUuid : undefined,
  });

  if (!parsed.success) {
    const flat = parsed.error.flatten();
    const fieldErrors = Object.values(flat.fieldErrors).flat();
    const message =
      [...flat.formErrors, ...fieldErrors].join("; ") || "Invalid form data";

    throw new UpstreamError(400, message);
  }

  return parsed.data;
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return "Unexpected error";
}

const uploadRoute = createRoute({
  method: "post",
  path: "/skins",
  tags: ["mineskin"],
  description:
    "Upload a skin to MineSkin with a required cape and wait for completion.",
  request: {
    query: uploadQuerySchema,
    body: {
      content: {
        "multipart/form-data": {
          schema: z.object({
            file: z.any().openapi({
              type: "string",
              format: "binary",
              description: "PNG skin file to upload to MineSkin.",
            }),
            variant: uploadFormSchema.shape.variant,
            name: uploadNameSchema,
            capeUuid: uploadFormSchema.shape.capeUuid,
          }),
        },
      },
    },
  },
  responses: {
    200: {
      description: "MineSkin job completed successfully.",
      content: {
        "application/json": {
          schema: mineSkinSanitizedResponseSchema,
        },
      },
    },
    400: {
      description: "Invalid request payload.",
      content: {
        "application/json": {
          schema: z.object({ error: z.string() }),
        },
      },
    },
    502: {
      description: "MineSkin returned an error.",
      content: {
        "application/json": {
          schema: z.object({ error: z.string() }),
        },
      },
    },
    500: {
      description: "MineSkin proxy configuration error.",
      content: {
        "application/json": {
          schema: z.object({ error: z.string() }),
        },
      },
    },
    504: {
      description: "Timed out waiting for MineSkin to finish processing.",
      content: {
        "application/json": {
          schema: z.object({ error: z.string() }),
        },
      },
    },
  },
});

mineskinRouter.openapi(uploadRoute, async (c) => {
  let waitMs = DEFAULT_POLL_INTERVAL_MS;
  try {
    const query = c.req.valid("query");
    waitMs = query.waitMs ?? DEFAULT_POLL_INTERVAL_MS;
  } catch (error) {
    return c.json({ error: toErrorMessage(error) }, 400);
  }

  let formData: FormData;
  try {
    formData = await c.req.formData();
  } catch (_error) {
    return c.json({ error: "Failed to parse multipart form data" }, 400);
  }

  const file = formData.get("file");
  if (!isFileLike(file)) {
    return c.json({ error: "A skin file must be provided" }, 400);
  }

  try {
    const parsedForm = parseUploadForm(formData);

    const supportedCapes = await getSupportedCapes();
    if (!supportedCapes.some((cape) => cape.uuid === parsedForm.capeUuid)) {
      return c.json({ error: "Requested cape is not supported" }, 400);
    }

    const upstreamFormData = new UndiciFormData();
    upstreamFormData.set("file", file);
    upstreamFormData.set("variant", parsedForm.variant);
    upstreamFormData.set("cape", parsedForm.capeUuid);
    if (parsedForm.name) {
      upstreamFormData.set("name", parsedForm.name);
    }

    const job = await enqueueMineSkinJob(upstreamFormData);
    const result = await pollMineSkinJob(job.id, waitMs);

    return c.json(result, 200);
  } catch (error) {
    console.error("MineSkin upload failed", error);
    if (error instanceof ConfigurationError) {
      return c.json({ error: error.message }, 500);
    }

    if (error instanceof UpstreamError) {
      const status = normalizeStatus(error.status, [400, 502, 504], 502);
      if (status === 400) {
        return c.json({ error: error.message }, 400);
      }
      if (status === 504) {
        return c.json({ error: error.message }, 504);
      }
      return c.json({ error: error.message }, 502);
    }

    return c.json({ error: toErrorMessage(error) }, 500);
  }
});

const jobStatusRoute = createRoute({
  method: "get",
  path: "/jobs/{jobId}",
  tags: ["mineskin"],
  description: "Retrieve the status of a MineSkin job.",
  request: {
    params: z.object({
      jobId: z.string().describe("Identifier of the MineSkin job."),
    }),
  },
  responses: {
    200: {
      description: "Job retrieved successfully.",
      content: {
        "application/json": {
          schema: mineSkinSanitizedResponseSchema,
        },
      },
    },
    404: {
      description: "Job could not be found.",
      content: {
        "application/json": {
          schema: z.object({ error: z.string() }),
        },
      },
    },
    502: {
      description: "MineSkin returned an error.",
      content: {
        "application/json": {
          schema: z.object({ error: z.string() }),
        },
      },
    },
    500: {
      description: "MineSkin proxy configuration error.",
      content: {
        "application/json": {
          schema: z.object({ error: z.string() }),
        },
      },
    },
  },
});

mineskinRouter.openapi(jobStatusRoute, async (c) => {
  const { jobId } = c.req.valid("param");

  try {
    const job = await fetchMineSkinJob(jobId);
    return c.json(sanitizeMineSkinJobResponse(job), 200);
  } catch (error) {
    console.error(`Failed to fetch MineSkin job ${jobId}`, error);
    if (error instanceof ConfigurationError) {
      return c.json({ error: error.message }, 500);
    }

    if (error instanceof UpstreamError) {
      const status = normalizeStatus(error.status, [404, 502], 502);
      if (status === 404) {
        return c.json({ error: error.message }, 404);
      }
      return c.json({ error: error.message }, 502);
    }

    return c.json({ error: toErrorMessage(error) }, 502);
  }
});

const supportedCapesRoute = createRoute({
  method: "get",
  path: "/capes",
  tags: ["mineskin"],
  description: "List MineSkin capes supported by the proxy.",
  responses: {
    200: {
      description: "List of supported capes.",
      content: {
        "application/json": {
          schema: z.object({ capes: z.array(mineSkinCapeSchema) }),
        },
      },
    },
    502: {
      description: "MineSkin returned an error.",
      content: {
        "application/json": {
          schema: z.object({ error: z.string() }),
        },
      },
    },
    500: {
      description: "MineSkin proxy configuration error.",
      content: {
        "application/json": {
          schema: z.object({ error: z.string() }),
        },
      },
    },
  },
});

mineskinRouter.openapi(supportedCapesRoute, async (c) => {
  try {
    const capes = await getSupportedCapes();
    return c.json({ capes }, 200);
  } catch (error) {
    console.error("Failed to fetch MineSkin capes", error);
    if (error instanceof ConfigurationError) {
      return c.json({ error: error.message }, 500);
    }
    if (error instanceof UpstreamError) {
      return c.json({ error: error.message }, 502);
    }
    return c.json({ error: toErrorMessage(error) }, 502);
  }
});

const capeSupportRoute = createRoute({
  method: "get",
  path: "/cape-support",
  tags: ["mineskin"],
  description:
    "Check whether the configured MineSkin account has cape grants and list supported capes.",
  responses: {
    200: {
      description: "Cape support information.",
      content: {
        "application/json": {
          schema: capeSupportResponseSchema,
        },
      },
    },
    502: {
      description: "MineSkin returned an error.",
      content: {
        "application/json": {
          schema: z.object({ error: z.string() }),
        },
      },
    },
    500: {
      description: "MineSkin proxy configuration error.",
      content: {
        "application/json": {
          schema: z.object({ error: z.string() }),
        },
      },
    },
  },
});

mineskinRouter.openapi(capeSupportRoute, async (c) => {
  try {
    const [hasCapeGrant, capes] = await Promise.all([
      fetchMineSkinCapeGrant(),
      getSupportedCapes(),
    ]);

    if (!hasCapeGrant) {
      return c.json({ hasCapeGrant, capes: [] }, 200);
    }

    return c.json({ hasCapeGrant, capes }, 200);
  } catch (error) {
    console.error("Failed to fetch MineSkin cape support", error);
    if (error instanceof ConfigurationError) {
      return c.json({ error: error.message }, 500);
    }
    if (error instanceof UpstreamError) {
      return c.json({ error: error.message }, 502);
    }
    return c.json({ error: toErrorMessage(error) }, 502);
  }
});

const decryptUrlRoute = createRoute({
  method: "get",
  path: "/decrypt-url",
  tags: ["mineskin"],
  description: "Decrypt an encrypted MineSkin URL back to the original URL.",
  request: {
    query: z.object({
      encryptedUrl: z.string().describe("The encrypted URL to decrypt."),
    }),
  },
  responses: {
    200: {
      description: "Decrypted URL.",
      content: {
        "application/json": {
          schema: z.object({ url: z.string() }),
        },
      },
    },
    400: {
      description: "Invalid encrypted URL.",
      content: {
        "application/json": {
          schema: z.object({ error: z.string() }),
        },
      },
    },
    500: {
      description: "Configuration error.",
      content: {
        "application/json": {
          schema: z.object({ error: z.string() }),
        },
      },
    },
  },
});

mineskinRouter.openapi(decryptUrlRoute, async (c) => {
  const { encryptedUrl } = c.req.valid("query");

  try {
    const decryptedUrl = decryptUrl(encryptedUrl);
    return c.json({ url: decryptedUrl }, 200);
  } catch (error) {
    if (error instanceof ConfigurationError) {
      return c.json({ error: error.message }, 500);
    }
    return c.json({ error: toErrorMessage(error) }, 400);
  }
});
