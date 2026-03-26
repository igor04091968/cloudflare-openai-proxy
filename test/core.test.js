import test from "node:test";
import assert from "node:assert/strict";

import {
  buildDedupeKey,
  deriveSeverity,
  expectedHttpStatuses,
  isNodeStale,
  normalizeSlug,
  parseTarget,
} from "../src/core.js";

test("normalizeSlug makes stable URL-safe slugs", () => {
  assert.equal(normalizeSlug(" GW 2 / Primary "), "gw-2-primary");
  assert.equal(normalizeSlug("###", "fallback"), "fallback");
});

test("expectedHttpStatuses falls back to safe defaults", () => {
  assert.deepEqual(expectedHttpStatuses(), [200, 201, 202, 204, 301, 302, 307, 308]);
  assert.deepEqual(expectedHttpStatuses(["200", "418", "999"]), [200, 418]);
});

test("parseTarget accepts URLs and host-port targets", () => {
  const httpTarget = parseTarget("https://example.com/health", "https");
  assert.equal(httpTarget.host, "example.com");
  assert.equal(httpTarget.port, 443);

  const tcpTarget = parseTarget("127.0.0.1:1080", "tcp");
  assert.equal(tcpTarget.host, "127.0.0.1");
  assert.equal(tcpTarget.port, 1080);
});

test("isNodeStale uses expected heartbeat threshold", () => {
  const now = Date.parse("2026-03-26T00:10:00.000Z");
  assert.equal(isNodeStale("2026-03-26T00:09:10.000Z", 60, now), false);
  assert.equal(isNodeStale("2026-03-26T00:07:00.000Z", 60, now), true);
});

test("dedupe and severity helpers stay deterministic", () => {
  assert.equal(buildDedupeKey("node_stale", "abc"), "node_stale:abc");
  assert.equal(deriveSeverity("fail"), "critical");
  assert.equal(deriveSeverity("warn"), "warning");
});

test("normalizeSlug keeps node references stable for channel upserts", () => {
  assert.equal(normalizeSlug("GW-1"), "gw-1");
  assert.equal(normalizeSlug("Gateway 1"), "gateway-1");
});
