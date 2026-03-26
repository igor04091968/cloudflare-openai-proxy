import {
  DEFAULT_HEARTBEAT_SEC,
  DEFAULT_HTTP_TIMEOUT_MS,
  HttpError,
  buildDedupeKey,
  coerceInteger,
  deriveSeverity,
  errorJson,
  expectedHttpStatuses,
  isNodeStale,
  json,
  normalizeSlug,
  nowIso,
  okEnvelope,
  parseTarget,
  readJson,
  sha256Hex,
  statusFromCheckResult,
} from "./core.js";

const AI_DEFAULT_MODEL = "@cf/meta/llama-3.1-8b-instruct";

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (error) {
      if (error instanceof HttpError) {
        return errorJson(error.status, error.code, error.message);
      }
      console.error("unhandled error", error);
      return errorJson(500, "internal_error", "Unexpected worker error");
    }
  },

  async scheduled(controller, env, ctx) {
    ctx.waitUntil(runScheduledSweep(env, controller.scheduledTime));
  },
};

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";

  if (request.method === "GET" && path === "/") {
    return json(
      okEnvelope({
        service: "proxy-reliability-control-plane",
        version: "0.1.0",
        time: nowIso(),
      }),
    );
  }

  if (request.method === "GET" && path === "/healthz") {
    return json(okEnvelope({ status: "ok", time: nowIso() }));
  }

  if (request.method === "POST" && path === "/v1/admin/bootstrap") {
    await requireAdmin(request, env);
    const body = await readJson(request);
    const result = await bootstrapProject(env, body);
    return json(okEnvelope(result), { status: 201 });
  }

  if (request.method === "POST" && path === "/v1/admin/nodes") {
    await requireAdmin(request, env);
    const body = await readJson(request);
    const result = await upsertNode(env, body);
    return json(okEnvelope(result), { status: 201 });
  }

  if (request.method === "POST" && path === "/v1/admin/channels") {
    await requireAdmin(request, env);
    const body = await readJson(request);
    const result = await upsertChannel(env, body);
    return json(okEnvelope(result), { status: 201 });
  }

  if (request.method === "GET" && path.startsWith("/v1/admin/projects/") && path.endsWith("/status")) {
    await requireAdmin(request, env);
    const projectSlug = path.split("/")[4];
    const result = await getProjectStatus(env, projectSlug);
    return json(okEnvelope(result));
  }

  if (request.method === "GET" && path === "/v1/admin/incidents") {
    await requireAdmin(request, env);
    const projectSlug = url.searchParams.get("project");
    const result = await listIncidents(env, projectSlug);
    return json(okEnvelope({ incidents: result }));
  }

  if (request.method === "POST" && path.startsWith("/v1/admin/incidents/") && path.endsWith("/resolve")) {
    await requireAdmin(request, env);
    const incidentId = path.split("/")[4];
    const result = await resolveIncident(env, incidentId, "resolved_by_admin");
    return json(okEnvelope(result));
  }

  if (request.method === "POST" && path.startsWith("/v1/admin/incidents/") && path.endsWith("/ai-analyze")) {
    await requireAdmin(request, env);
    const incidentId = path.split("/")[4];
    const result = await analyzeIncidentWithAi(env, incidentId);
    return json(okEnvelope(result));
  }

  if (request.method === "POST" && path === "/v1/agent/heartbeat") {
    const token = await requireAgent(request, env);
    const body = await readJson(request);
    const result = await ingestHeartbeat(env, token, body, request);
    return json(okEnvelope(result), { status: 202 });
  }

  if (request.method === "GET" && path.startsWith("/v1/status/")) {
    const projectSlug = path.split("/")[3];
    const token = url.searchParams.get("token");
    const result = await getPublicStatus(env, projectSlug, token);
    return json(okEnvelope(result));
  }

  return errorJson(404, "not_found", "Route not found");
}

async function requireAdmin(request, env) {
  const expected = env.ADMIN_TOKEN;
  const actual = bearerToken(request);
  if (!expected) {
    throw new HttpError(500, "missing_admin_token", "ADMIN_TOKEN is not configured");
  }
  if (!actual || actual !== expected) {
    throw new HttpError(401, "unauthorized", "Admin token is required");
  }
}

async function requireAgent(request, env) {
  const token = bearerToken(request) || request.headers.get("x-agent-token");
  if (!token) {
    throw new HttpError(401, "unauthorized", "Agent token is required");
  }

  const hash = await sha256Hex(token);
  const row = await env.DB.prepare(
    `SELECT at.id, at.name, at.project_id, p.slug AS project_slug
     FROM agent_tokens at
     JOIN projects p ON p.id = at.project_id
     WHERE at.token_hash = ?1 AND at.revoked_at IS NULL`,
  )
    .bind(hash)
    .first();

  if (!row) {
    throw new HttpError(401, "unauthorized", "Agent token is invalid");
  }

  await env.DB.prepare("UPDATE agent_tokens SET last_used_at = ?1 WHERE id = ?2")
    .bind(nowIso(), row.id)
    .run();

  return row;
}

function bearerToken(request) {
  const header = request.headers.get("authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

async function bootstrapProject(env, body) {
  assertDb(env);
  const tenantSlug = normalizeSlug(body?.tenant?.slug || body?.tenantSlug, "tenant");
  const tenantName = String(body?.tenant?.name || body?.tenantName || tenantSlug);
  const projectSlug = normalizeSlug(body?.project?.slug || body?.projectSlug, "project");
  const projectName = String(body?.project?.name || body?.projectName || projectSlug);
  const now = nowIso();

  const tenantId = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO tenants (id, slug, name, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?4)
     ON CONFLICT(slug) DO UPDATE SET name = excluded.name, updated_at = excluded.updated_at`,
  )
    .bind(tenantId, tenantSlug, tenantName, now)
    .run();

  const tenant = await env.DB.prepare("SELECT id, slug, name FROM tenants WHERE slug = ?1").bind(tenantSlug).first();
  const projectId = crypto.randomUUID();
  const publicStatusToken = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO projects (id, tenant_id, slug, name, public_status_token, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
     ON CONFLICT(slug) DO UPDATE SET
       tenant_id = excluded.tenant_id,
       name = excluded.name,
       updated_at = excluded.updated_at`,
  )
    .bind(projectId, tenant.id, projectSlug, projectName, publicStatusToken, now)
    .run();

  const project = await env.DB.prepare(
    "SELECT id, slug, name, public_status_token FROM projects WHERE slug = ?1",
  )
    .bind(projectSlug)
    .first();

  const agentToken = crypto.randomUUID();
  const agentTokenHash = await sha256Hex(agentToken);
  await env.DB.prepare(
    `INSERT INTO agent_tokens (id, project_id, name, token_hash, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5)`,
  )
    .bind(crypto.randomUUID(), project.id, `${project.slug}-default-agent`, agentTokenHash, now)
    .run();

  return {
    tenant,
    project,
    issued: {
      agentToken,
      publicStatusToken: project.public_status_token,
    },
  };
}

async function upsertNode(env, body) {
  assertDb(env);
  const project = await requireProject(env, body.projectSlug);
  const slug = normalizeSlug(body.slug || body.name, "node");
  const now = nowIso();
  const nodeId = crypto.randomUUID();
  const expectedHeartbeatSec = coerceInteger(
    body.expectedHeartbeatSec,
    DEFAULT_HEARTBEAT_SEC,
    15,
    3600,
  );

  await env.DB.prepare(
    `INSERT INTO nodes (
       id, project_id, slug, name, hostname, region, expected_heartbeat_sec, status,
       metadata_json, created_at, updated_at
     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'unknown', ?8, ?9, ?9)
     ON CONFLICT(project_id, slug) DO UPDATE SET
       name = excluded.name,
       hostname = excluded.hostname,
       region = excluded.region,
       expected_heartbeat_sec = excluded.expected_heartbeat_sec,
       metadata_json = excluded.metadata_json,
       updated_at = excluded.updated_at`,
  )
    .bind(
      nodeId,
      project.id,
      slug,
      body.name || slug,
      body.hostname || null,
      body.region || null,
      expectedHeartbeatSec,
      JSON.stringify(body.metadata || {}),
      now,
    )
    .run();

  return env.DB.prepare(
    `SELECT id, project_id, slug, name, hostname, region, expected_heartbeat_sec, status, last_heartbeat_at
     FROM nodes WHERE project_id = ?1 AND slug = ?2`,
  )
    .bind(project.id, slug)
    .first();
}

async function upsertChannel(env, body) {
  assertDb(env);
  const project = await requireProject(env, body.projectSlug);
  const node = body.nodeSlug ? await requireNode(env, project.id, body.nodeSlug) : null;
  const protocol = String(body.protocol || "").toLowerCase();
  if (!["http", "https", "head", "tcp", "tls"].includes(protocol)) {
    throw new HttpError(400, "invalid_protocol", "protocol must be one of http, https, head, tcp, tls");
  }

  const slug = normalizeSlug(body.slug || body.name || body.target, "channel");
  parseTarget(body.target, protocol === "head" ? "https" : protocol);
  const intervalSec = coerceInteger(body.intervalSec, 60, 15, 3600);
  const timeoutMs = coerceInteger(body.timeoutMs, DEFAULT_HTTP_TIMEOUT_MS, 1000, 30000);
  const now = nowIso();

  await env.DB.prepare(
    `INSERT INTO channels (
       id, project_id, node_id, slug, name, protocol, target, method, interval_sec, timeout_ms,
       expected_statuses_json, status, created_at, updated_at
     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'unknown', ?12, ?12)
     ON CONFLICT(project_id, slug) DO UPDATE SET
       node_id = excluded.node_id,
       name = excluded.name,
       protocol = excluded.protocol,
       target = excluded.target,
       method = excluded.method,
       interval_sec = excluded.interval_sec,
       timeout_ms = excluded.timeout_ms,
       expected_statuses_json = excluded.expected_statuses_json,
       updated_at = excluded.updated_at`,
  )
    .bind(
      crypto.randomUUID(),
      project.id,
      node?.id || null,
      slug,
      body.name || slug,
      protocol,
      body.target,
      protocol === "head" ? "HEAD" : body.method || null,
      intervalSec,
      timeoutMs,
      JSON.stringify(expectedHttpStatuses(body.expectedStatuses)),
      now,
    )
    .run();

  return env.DB.prepare(
    `SELECT id, project_id, node_id, slug, name, protocol, target, status, last_checked_at, last_error, consecutive_failures
     FROM channels WHERE project_id = ?1 AND slug = ?2`,
  )
    .bind(project.id, slug)
    .first();
}

async function ingestHeartbeat(env, token, body, request) {
  assertDb(env);
  const project = await requireProject(env, body.projectSlug || token.project_slug);
  if (project.id !== token.project_id) {
    throw new HttpError(403, "project_mismatch", "Agent token does not belong to this project");
  }

  const now = nowIso();
  const nodeSlug = normalizeSlug(body?.node?.slug || body?.nodeSlug || body?.node?.name, "node");
  const node = await upsertNode(env, {
    projectSlug: project.slug,
    slug: nodeSlug,
    name: body?.node?.name || body?.nodeName || nodeSlug,
    hostname: body?.node?.hostname || null,
    region: body?.node?.region || null,
    expectedHeartbeatSec: body?.node?.expectedHeartbeatSec || body?.expectedHeartbeatSec,
    metadata: body?.node?.metadata || body?.metrics || {},
  });

  const receivedAt = body.receivedAt || now;
  await env.DB.prepare(
    `UPDATE nodes
     SET status = ?1, last_heartbeat_at = ?2, last_heartbeat_ip = ?3, metadata_json = ?4, updated_at = ?5
     WHERE id = ?6`,
  )
    .bind(
      body.status === "degraded" ? "degraded" : "healthy",
      receivedAt,
      request.headers.get("cf-connecting-ip"),
      JSON.stringify(body?.node?.metadata || body?.metrics || {}),
      now,
      node.id,
    )
    .run();

  await env.DB.prepare(
    `INSERT INTO heartbeats (id, project_id, node_id, received_at, status, payload_json)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
  )
    .bind(crypto.randomUUID(), project.id, node.id, receivedAt, body.status || "healthy", JSON.stringify(body))
    .run();

  const checks = Array.isArray(body.checks) ? body.checks : [];
  const processedChecks = [];
  for (const check of checks) {
    const channel = await upsertChannel(env, {
      projectSlug: project.slug,
      nodeSlug: node.slug,
      slug: check.slug || check.name || check.target,
      name: check.name || check.slug || check.target,
      protocol: check.protocol,
      target: check.target,
      expectedStatuses: check.expectedStatuses,
      timeoutMs: check.timeoutMs,
      intervalSec: check.intervalSec,
      method: check.method,
    });
    const observedAt = check.observedAt || receivedAt;
    const status = check.status === "pass" ? "pass" : "fail";
    const nextConsecutiveFailures = status === "pass" ? 0 : (Number(channel.consecutive_failures || 0) + 1);

    await env.DB.prepare(
      `UPDATE channels
       SET status = ?1,
           last_checked_at = ?2,
           last_latency_ms = ?3,
           last_error = ?4,
           consecutive_failures = ?5,
           updated_at = ?6
       WHERE id = ?7`,
    )
      .bind(
        statusFromCheckResult(status),
        observedAt,
        check.latencyMs || null,
        check.error || null,
        nextConsecutiveFailures,
        now,
        channel.id,
      )
      .run();

    await env.DB.prepare(
      `INSERT INTO channel_results (id, channel_id, observed_at, status, latency_ms, details_json)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
    )
      .bind(
        crypto.randomUUID(),
        channel.id,
        observedAt,
        status,
        check.latencyMs || null,
        JSON.stringify(check),
      )
      .run();

    await syncChannelIncident(env, project.id, channel.id, status, check.error || "Agent-reported failure");
    processedChecks.push({
      slug: channel.slug,
      status,
      latencyMs: check.latencyMs || null,
    });
  }

  await syncNodeStaleIncident(env, project.id, node.id, false);

  return {
    project: project.slug,
    node: node.slug,
    receivedAt,
    checks: processedChecks,
  };
}

async function getPublicStatus(env, projectSlug, token) {
  assertDb(env);
  const project = await env.DB.prepare(
    "SELECT id, slug, name, public_status_token FROM projects WHERE slug = ?1",
  )
    .bind(projectSlug)
    .first();

  if (!project) {
    throw new HttpError(404, "project_not_found", `Project "${projectSlug}" was not found`);
  }
  if (!token || token !== project.public_status_token) {
    throw new HttpError(401, "unauthorized", "Public status token is required");
  }

  return getProjectStatus(env, project.slug);
}

async function getProjectStatus(env, projectSlug) {
  assertDb(env);
  const project = await requireProject(env, projectSlug);
  const nodes = await env.DB.prepare(
    `SELECT slug, name, hostname, region, status, last_heartbeat_at, expected_heartbeat_sec
     FROM nodes
     WHERE project_id = ?1
     ORDER BY slug`,
  )
    .bind(project.id)
    .all();
  const channels = await env.DB.prepare(
    `SELECT slug, name, protocol, target, status, last_checked_at, last_latency_ms, last_error, consecutive_failures
     FROM channels
     WHERE project_id = ?1
     ORDER BY slug`,
  )
    .bind(project.id)
    .all();
  const incidents = await env.DB.prepare(
    `SELECT id, kind, severity, status, title, summary, first_seen_at, last_seen_at, resolved_at, ai_summary
     FROM incidents
     WHERE project_id = ?1
     ORDER BY
       CASE status WHEN 'open' THEN 0 ELSE 1 END,
       last_seen_at DESC`,
  )
    .bind(project.id)
    .all();

  const overall = deriveOverallStatus(nodes.results, channels.results, incidents.results);
  return {
    project: { slug: project.slug, name: project.name },
    overall,
    nodes: nodes.results,
    channels: channels.results,
    incidents: incidents.results,
  };
}

async function listIncidents(env, projectSlug) {
  assertDb(env);
  if (!projectSlug) {
    return env.DB.prepare(
      `SELECT id, project_id, node_id, channel_id, kind, severity, status, title, summary, ai_summary, first_seen_at, last_seen_at, resolved_at
       FROM incidents
       ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, last_seen_at DESC
       LIMIT 100`,
    ).all().then((res) => res.results);
  }

  const project = await requireProject(env, projectSlug);
  return env.DB.prepare(
    `SELECT id, project_id, node_id, channel_id, kind, severity, status, title, summary, ai_summary, first_seen_at, last_seen_at, resolved_at
     FROM incidents
     WHERE project_id = ?1
     ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, last_seen_at DESC
     LIMIT 100`,
  )
    .bind(project.id)
    .all()
    .then((res) => res.results);
}

async function resolveIncident(env, incidentId, reason) {
  assertDb(env);
  const now = nowIso();
  await env.DB.prepare(
    `UPDATE incidents
     SET status = 'resolved', resolved_at = ?1, last_seen_at = ?1, updated_at = ?1
     WHERE id = ?2`,
  )
    .bind(now, incidentId)
    .run();
  await appendIncidentEvent(env, incidentId, "resolved", { reason });
  return env.DB.prepare("SELECT * FROM incidents WHERE id = ?1").bind(incidentId).first();
}

async function analyzeIncidentWithAi(env, incidentId) {
  assertDb(env);
  if (!env.AI || typeof env.AI.run !== "function") {
    throw new HttpError(501, "ai_unavailable", "Workers AI binding is not configured");
  }

  const incident = await env.DB.prepare(
    `SELECT i.id, i.kind, i.severity, i.status, i.title, i.summary, i.first_seen_at, i.last_seen_at,
            p.slug AS project_slug, n.slug AS node_slug, c.slug AS channel_slug, c.target AS channel_target, c.last_error
     FROM incidents i
     JOIN projects p ON p.id = i.project_id
     LEFT JOIN nodes n ON n.id = i.node_id
     LEFT JOIN channels c ON c.id = i.channel_id
     WHERE i.id = ?1`,
  )
    .bind(incidentId)
    .first();

  if (!incident) {
    throw new HttpError(404, "incident_not_found", `Incident "${incidentId}" was not found`);
  }

  const model = env.AI_MODEL || AI_DEFAULT_MODEL;
  const prompt = [
    "You are an SRE assistant for a proxy platform.",
    "Summarize the incident in 3 short bullets.",
    "Then provide one likely root cause and one safe next action.",
    "Do not suggest dangerous shell commands.",
    "",
    JSON.stringify(incident, null, 2),
  ].join("\n");

  const response = await env.AI.run(model, {
    prompt,
    max_tokens: 300,
  });

  const text = extractAiText(response);
  await env.DB.prepare("UPDATE incidents SET ai_summary = ?1, updated_at = ?2 WHERE id = ?3")
    .bind(text, nowIso(), incidentId)
    .run();
  await appendIncidentEvent(env, incidentId, "ai_analysis", { model, text });

  return { incidentId, model, analysis: text };
}

async function runScheduledSweep(env, scheduledTime = Date.now()) {
  assertDb(env);
  const now = nowIso(scheduledTime);

  const nodes = await env.DB.prepare(
    `SELECT id, project_id, slug, expected_heartbeat_sec, last_heartbeat_at
     FROM nodes`,
  ).all();

  for (const node of nodes.results) {
    const stale = isNodeStale(node.last_heartbeat_at, node.expected_heartbeat_sec || DEFAULT_HEARTBEAT_SEC, scheduledTime);
    await env.DB.prepare(
      "UPDATE nodes SET status = ?1, updated_at = ?2 WHERE id = ?3",
    )
      .bind(stale ? "stale" : "healthy", now, node.id)
      .run();
    await syncNodeStaleIncident(env, node.project_id, node.id, stale);
  }

  const channels = await env.DB.prepare(
    `SELECT id, project_id, protocol, target, timeout_ms, expected_statuses_json
     FROM channels`,
  ).all();

  for (const channel of channels.results) {
    if (!["http", "https", "head"].includes(channel.protocol)) {
      continue;
    }
    const checkResult = await executeChannelCheck(channel);
    await env.DB.prepare(
      `UPDATE channels
       SET status = ?1,
           last_checked_at = ?2,
           last_latency_ms = ?3,
           last_error = ?4,
           consecutive_failures = CASE WHEN ?5 = 'pass' THEN 0 ELSE consecutive_failures + 1 END,
           updated_at = ?2
       WHERE id = ?6`,
    )
      .bind(
        statusFromCheckResult(checkResult.status),
        checkResult.observedAt,
        checkResult.latencyMs,
        checkResult.error,
        checkResult.status,
        channel.id,
      )
      .run();

    await env.DB.prepare(
      `INSERT INTO channel_results (id, channel_id, observed_at, status, latency_ms, details_json)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
    )
      .bind(
        crypto.randomUUID(),
        channel.id,
        checkResult.observedAt,
        checkResult.status,
        checkResult.latencyMs,
        JSON.stringify(checkResult),
      )
      .run();

    await syncChannelIncident(
      env,
      channel.project_id,
      channel.id,
      checkResult.status,
      checkResult.error || "Scheduled check failed",
    );
  }
}

async function executeChannelCheck(channel) {
  const protocol = channel.protocol === "head" ? "https" : channel.protocol;
  const observedAt = nowIso();
  const timeoutMs = channel.timeout_ms || DEFAULT_HTTP_TIMEOUT_MS;
  const startedAt = Date.now();

  try {
    const { url } = parseTarget(channel.target, protocol);
    const method = channel.protocol === "head" ? "HEAD" : "GET";
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    const response = await fetch(url.toString(), {
      method,
      redirect: "manual",
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    const allowedStatuses = expectedHttpStatuses(JSON.parse(channel.expected_statuses_json || "[]"));
    const passed = allowedStatuses.includes(response.status);
    return {
      status: passed ? "pass" : "fail",
      observedAt,
      latencyMs: Date.now() - startedAt,
      error: passed ? null : `Unexpected HTTP status ${response.status}`,
    };
  } catch (error) {
    return {
      status: "fail",
      observedAt,
      latencyMs: Date.now() - startedAt,
      error: error?.message || "Unknown check failure",
    };
  }
}

async function syncNodeStaleIncident(env, projectId, nodeId, stale) {
  const dedupeKey = buildDedupeKey("node_stale", nodeId);
  if (!stale) {
    const incident = await findOpenIncidentByKey(env, dedupeKey);
    if (incident) {
      await resolveIncident(env, incident.id, "node_recovered");
    }
    return;
  }

  const node = await env.DB.prepare("SELECT slug, name FROM nodes WHERE id = ?1").bind(nodeId).first();
  await openOrRefreshIncident(env, {
    projectId,
    nodeId,
    channelId: null,
    dedupeKey,
    kind: "node_stale",
    severity: "critical",
    title: `Node ${node.slug} stopped sending heartbeats`,
    summary: `${node.name || node.slug} exceeded the heartbeat threshold and is considered stale.`,
  });
}

async function syncChannelIncident(env, projectId, channelId, status, errorMessage) {
  const dedupeKey = buildDedupeKey("channel_down", channelId);
  if (status === "pass") {
    const incident = await findOpenIncidentByKey(env, dedupeKey);
    if (incident) {
      await resolveIncident(env, incident.id, "channel_recovered");
    }
    return;
  }

  const channel = await env.DB.prepare("SELECT slug, name, target FROM channels WHERE id = ?1").bind(channelId).first();
  await openOrRefreshIncident(env, {
    projectId,
    nodeId: null,
    channelId,
    dedupeKey,
    kind: "channel_down",
    severity: deriveSeverity(status),
    title: `Channel ${channel.slug} is unhealthy`,
    summary: errorMessage || `Scheduled or agent check failed for ${channel.target}`,
  });
}

async function openOrRefreshIncident(env, incident) {
  const now = nowIso();
  const existing = await findOpenIncidentByKey(env, incident.dedupeKey);
  if (existing) {
    await env.DB.prepare(
      `UPDATE incidents
       SET severity = ?1, summary = ?2, last_seen_at = ?3, updated_at = ?3
       WHERE id = ?4`,
    )
      .bind(incident.severity, incident.summary, now, existing.id)
      .run();
    await appendIncidentEvent(env, existing.id, "observed", { summary: incident.summary });
    return existing.id;
  }

  const incidentId = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO incidents (
       id, project_id, node_id, channel_id, dedupe_key, kind, severity, status, title, summary,
       first_seen_at, last_seen_at, created_at, updated_at
     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'open', ?8, ?9, ?10, ?10, ?10, ?10)`,
  )
    .bind(
      incidentId,
      incident.projectId,
      incident.nodeId,
      incident.channelId,
      incident.dedupeKey,
      incident.kind,
      incident.severity,
      incident.title,
      incident.summary,
      now,
    )
    .run();
  await appendIncidentEvent(env, incidentId, "opened", { summary: incident.summary });
  return incidentId;
}

async function appendIncidentEvent(env, incidentId, kind, payload) {
  await env.DB.prepare(
    `INSERT INTO incident_events (id, incident_id, kind, payload_json, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5)`,
  )
    .bind(crypto.randomUUID(), incidentId, kind, JSON.stringify(payload || {}), nowIso())
    .run();
}

async function findOpenIncidentByKey(env, dedupeKey) {
  return env.DB.prepare(
    "SELECT id, status FROM incidents WHERE dedupe_key = ?1 AND status = 'open' LIMIT 1",
  )
    .bind(dedupeKey)
    .first();
}

function deriveOverallStatus(nodes, channels, incidents) {
  if (incidents.some((incident) => incident.status === "open" && incident.severity === "critical")) {
    return "critical";
  }
  if (
    nodes.some((node) => ["degraded", "stale"].includes(node.status)) ||
    channels.some((channel) => channel.status === "degraded")
  ) {
    return "degraded";
  }
  if (nodes.length === 0 && channels.length === 0) {
    return "empty";
  }
  return "healthy";
}

async function requireProject(env, projectSlug) {
  const project = await env.DB.prepare("SELECT id, slug, name, public_status_token FROM projects WHERE slug = ?1")
    .bind(projectSlug)
    .first();
  if (!project) {
    throw new HttpError(404, "project_not_found", `Project "${projectSlug}" was not found`);
  }
  return project;
}

async function requireNode(env, projectId, nodeSlug) {
  const node = await env.DB.prepare("SELECT * FROM nodes WHERE project_id = ?1 AND slug = ?2")
    .bind(projectId, nodeSlug)
    .first();
  if (!node) {
    throw new HttpError(404, "node_not_found", `Node "${nodeSlug}" was not found`);
  }
  return node;
}

function assertDb(env) {
  if (!env.DB || typeof env.DB.prepare !== "function") {
    throw new HttpError(500, "missing_db", "D1 binding DB is not configured");
  }
}

function extractAiText(response) {
  if (typeof response === "string") return response;
  if (response?.result?.response) return response.result.response;
  if (response?.response) return response.response;
  if (Array.isArray(response?.result)) return response.result.join("\n");
  return JSON.stringify(response);
}
