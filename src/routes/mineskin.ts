import { setTimeout as delay } from "node:timers/promises";
import { URL } from "node:url";
import { createRoute, OpenAPIHono, z } from "@hono/zod-openapi";
import { FormData as UndiciFormData, fetch as undiciFetch } from "undici";

const MINESKIN_BASE_URL = "https://api.mineskin.org/v2";
const MINESKIN_USER_AGENT = "Axolotl-MineSkin-Proxy/1.0";
const DEFAULT_POLL_INTERVAL_MS = 1_000;
const MAX_POLL_DURATION_MS = 5 * 60 * 1_000;
const CAPE_CACHE_TTL_MS = 5 * 60 * 1_000;

const jobStatusSchema = z.enum([
  "unknown",
  "waiting",
  "active",
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
    result: z.string().optional(),
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
    hash: mineSkinSkinHashesSchema.optional(),
    url: mineSkinSkinUrlsSchema.optional(),
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

const mineSkinJobSuccessSchema = z
  .object({
    success: z.literal(true),
    job: mineSkinJobDetailsSchema,
    skin: mineSkinSkinSchema.optional(),
    rateLimit: mineSkinRateLimitInfoSchema.optional(),
    usage: mineSkinUsageInfoSchema.optional(),
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

const mineSkinCapeSchema = z.object({
  uuid: z.string(),
  alias: z.string(),
  url: z.string().url(),
});

type MineSkinError = z.infer<typeof mineSkinErrorSchema>;
type MineSkinJobDetails = z.infer<typeof mineSkinJobDetailsSchema>;
type MineSkinJobSuccessResponse = z.infer<typeof mineSkinJobSuccessSchema>;
type MineSkinCape = z.infer<typeof mineSkinCapeSchema>;

type MineSkinRateLimitInfo = z.infer<typeof mineSkinRateLimitInfoSchema>;
type MineSkinUsageInfo = z.infer<typeof mineSkinUsageInfoSchema>;

type MineSkinGenericResponse = {
  success?: boolean | undefined;
  errors?: MineSkinError[] | undefined;
  warnings?: MineSkinError[] | undefined;
  messages?: MineSkinError[] | undefined;
  rateLimit?: MineSkinRateLimitInfo | undefined;
  usage?: MineSkinUsageInfo | undefined;
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

async function requestMineSkinJob(
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
    return mineSkinJobSuccessSchema.parse(data);
  } catch {
    throw new UpstreamError(502, "Unexpected MineSkin job response");
  }
}

async function pollMineSkinJob(
  jobId: string,
  waitMs: number,
): Promise<MineSkinJobSuccessResponse> {
  const maxAttempts = Math.max(1, Math.ceil(MAX_POLL_DURATION_MS / waitMs));

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const jobData = await requestMineSkinJob(jobId);
    const { status } = jobData.job;

    if (status === "completed") {
      if (!jobData.skin) {
        throw new UpstreamError(502, "MineSkin job completed but no skin data provided");
      }
      return jobData;
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
  } catch {
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
    return z.array(mineSkinCapeSchema).parse(capes);
  } catch {
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
          schema: mineSkinJobSuccessSchema,
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
          schema: mineSkinJobSuccessSchema,
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
    const job = await requestMineSkinJob(jobId);
    return c.json(job, 200);
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
