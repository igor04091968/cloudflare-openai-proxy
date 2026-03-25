export const DEFAULT_HTTP_TIMEOUT_MS = 5000;
export const DEFAULT_HEARTBEAT_SEC = 60;
export const STALE_GRACE_MULTIPLIER = 2;

export function json(data, init = {}) {
  const headers = new Headers(init.headers || {});
  if (!headers.has("content-type")) {
    headers.set("content-type", "application/json; charset=utf-8");
  }
  return new Response(JSON.stringify(data, null, 2), { ...init, headers });
}

export function errorJson(status, code, message, extra = {}) {
  return json({ ok: false, error: { code, message, ...extra } }, { status });
}

export async function readJson(request) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) {
    throw new HttpError(415, "unsupported_media_type", "Expected application/json body");
  }
  return request.json();
}

export function nowIso(now = Date.now()) {
  return new Date(now).toISOString();
}

export function normalizeSlug(value, fallback = "item") {
  const normalized = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return normalized || fallback;
}

export function coerceInteger(value, fallback, min = null, max = null) {
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed)) return fallback;
  let result = parsed;
  if (min !== null) result = Math.max(min, result);
  if (max !== null) result = Math.min(max, result);
  return result;
}

export function statusFromCheckResult(status) {
  return status === "pass" ? "healthy" : "degraded";
}

export function deriveSeverity(status) {
  return status === "fail" ? "critical" : "warning";
}

export function expectedHttpStatuses(raw) {
  if (!Array.isArray(raw) || raw.length === 0) return [200, 201, 202, 204, 301, 302, 307, 308];
  return raw
    .map((item) => Number.parseInt(item, 10))
    .filter((item) => Number.isInteger(item) && item >= 100 && item <= 599);
}

export function parseTarget(target, protocol) {
  if (protocol === "http" || protocol === "https") {
    const url = new URL(target);
    return {
      url,
      host: url.hostname,
      port: Number.parseInt(url.port || (url.protocol === "https:" ? "443" : "80"), 10),
    };
  }

  const match = String(target || "").trim().match(/^([^:]+):(\d{1,5})$/);
  if (!match) {
    throw new HttpError(400, "invalid_target", `Expected host:port target, got "${target}"`);
  }
  return { host: match[1], port: Number.parseInt(match[2], 10) };
}

export function isNodeStale(lastHeartbeatAt, expectedHeartbeatSec, now = Date.now()) {
  if (!lastHeartbeatAt) return true;
  const lastTs = Date.parse(lastHeartbeatAt);
  if (!Number.isFinite(lastTs)) return true;
  return now - lastTs > expectedHeartbeatSec * STALE_GRACE_MULTIPLIER * 1000;
}

export function buildDedupeKey(kind, id) {
  return `${kind}:${id}`;
}

export function sha256Hex(value) {
  const data = new TextEncoder().encode(String(value));
  return crypto.subtle.digest("SHA-256", data).then((buffer) => {
    const bytes = new Uint8Array(buffer);
    return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  });
}

export class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.code = code;
  }
}

export function okEnvelope(data) {
  return { ok: true, ...data };
}
