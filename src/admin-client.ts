export const ADMIN_SECTIONS = {
  state: { label: "Application", path: "/state", icon: "◈" },
  services: { label: "Services", path: "/services", icon: "▦" },
  tasks: { label: "Background tasks", path: "/tasks", icon: "⌁" },
  plugins: { label: "Plugins", path: "/plugins", icon: "⬡" },
  routes: { label: "Routes", path: "/routes", icon: "⇄" },
  dependencies: { label: "Dependencies", path: "/dependencies", icon: "⌘" },
  config: { label: "Configuration", path: "/config", icon: "⚙" },
  lifecycle: { label: "Lifecycle", path: "/lifecycle", icon: "◷" },
  health: { label: "Health", path: "/health", icon: "♡" },
  diagnostics: { label: "Diagnostics", path: "/diagnostics", icon: "⌗" },
  events: { label: "Events", path: "/events", icon: "◌" },
  audit: { label: "Admin audit", path: "/audit", icon: "▤" },
} as const;

export type AdminSection = keyof typeof ADMIN_SECTIONS;
export type AdminData = Record<string, unknown> | unknown[];

const DEFAULT_MAX_RESPONSE_BYTES = 1_048_576;
const ERROR_CODE_PATTERN = /^[A-Za-z][A-Za-z0-9_.-]{0,126}$/;

export class AdminClientError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "AdminClientError";
    this.status = status;
    this.code = code;
  }
}

function validateApiBase(apiBase: string): string {
  if (
    typeof apiBase !== "string" ||
    !/^\/(?:[A-Za-z0-9_-]+)(?:\/[A-Za-z0-9_-]+)*\/?$/.test(apiBase) ||
    apiBase.length > 128
  ) {
    throw new TypeError("Admin API base must be a bounded same-origin path.");
  }
  return apiBase.replace(/\/$/, "");
}

async function readBoundedBody(response: Response, maxBytes: number): Promise<Uint8Array> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    if (!/^\d{1,10}$/.test(declared) || Number(declared) > maxBytes) {
      await response.body?.cancel();
      throw new AdminClientError(502, "admin.response-too-large", "Admin response is too large.");
    }
  }
  if (response.body === null) return new Uint8Array();

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      total += item.value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new AdminClientError(
          502,
          "admin.response-too-large",
          "Admin response is too large.",
        );
      }
      chunks.push(item.value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function parseErrorCode(body: Uint8Array): string {
  try {
    const decoded: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
    if (
      typeof decoded === "object" &&
      decoded !== null &&
      "code" in decoded &&
      typeof decoded.code === "string" &&
      ERROR_CODE_PATTERN.test(decoded.code)
    ) {
      return decoded.code;
    }
  } catch {
    // Do not copy remote error bodies into the browser UI.
  }
  return "admin.request-failed";
}

export function createAdminClient(
  fetcher: typeof fetch = fetch,
  apiBase = "/admin",
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
) {
  const base = validateApiBase(apiBase);
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 128 || maxResponseBytes > 16_777_216) {
    throw new RangeError("Admin response limit must be between 128 bytes and 16 MiB.");
  }

  return {
    async read(section: AdminSection): Promise<AdminData> {
      const definition = ADMIN_SECTIONS[section];
      if (definition === undefined) {
        throw new TypeError("Unknown Admin section.");
      }
      let response: Response;
      try {
        response = await fetcher(`${base}${definition.path}`, {
          method: "GET",
          credentials: "same-origin",
          cache: "no-store",
          redirect: "error",
          mode: "same-origin",
          referrerPolicy: "same-origin",
          headers: { accept: "application/json" },
        });
      } catch {
        throw new AdminClientError(0, "admin.unavailable", "Orbit Admin API is unavailable.");
      }
      const mediaType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
      if (response.redirected || mediaType !== "application/json") {
        await response.body?.cancel();
        throw new AdminClientError(502, "admin.invalid-response", "Admin returned an invalid response.");
      }
      const body = await readBoundedBody(response, maxResponseBytes);
      if (!response.ok) {
        const code = parseErrorCode(body);
        if (response.status === 401) {
          throw new AdminClientError(401, code, "Authentication is required to view this section.");
        }
        if (response.status === 403) {
          throw new AdminClientError(403, code, "Your account cannot view this section.");
        }
        throw new AdminClientError(response.status, code, "Admin could not load this section.");
      }
      try {
        const result: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
        if (typeof result !== "object" || result === null) throw new TypeError();
        return result as AdminData;
      } catch {
        throw new AdminClientError(502, "admin.invalid-response", "Admin returned invalid JSON.");
      }
    },
  };
}
