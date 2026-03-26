// src/core.js
var DEFAULT_HTTP_TIMEOUT_MS = 5e3;
var DEFAULT_HEARTBEAT_SEC = 60;
var STALE_GRACE_MULTIPLIER = 2;
function json(data, init = {}) {
  const headers = new Headers(init.headers || {});
  if (!headers.has("content-type")) {
    headers.set("content-type", "application/json; charset=utf-8");
  }
  return new Response(JSON.stringify(data, null, 2), { ...init, headers });
}
function errorJson(status, code, message, extra = {}) {
  return json({ ok: false, error: { code, message, ...extra } }, { status });
}
async function readJson(request) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) {
    throw new HttpError(415, "unsupported_media_type", "Expected application/json body");
  }
  return request.json();
}
function nowIso(now = Date.now()) {
  return new Date(now).toISOString();
}
function normalizeSlug(value, fallback = "item") {
  const normalized = String(value || "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return normalized || fallback;
}
function coerceInteger(value, fallback, min = null, max = null) {
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed)) return fallback;
  let result = parsed;
  if (min !== null) result = Math.max(min, result);
  if (max !== null) result = Math.min(max, result);
  return result;
}
function statusFromCheckResult(status) {
  return status === "pass" ? "healthy" : "degraded";
}
function deriveSeverity(status) {
  return status === "fail" ? "critical" : "warning";
}
function expectedHttpStatuses(raw) {
  if (!Array.isArray(raw) || raw.length === 0) return [200, 201, 202, 204, 301, 302, 307, 308];
  return raw.map((item) => Number.parseInt(item, 10)).filter((item) => Number.isInteger(item) && item >= 100 && item <= 599);
}
function parseTarget(target, protocol) {
  if (protocol === "http" || protocol === "https") {
    const url = new URL(target);
    return {
      url,
      host: url.hostname,
      port: Number.parseInt(url.port || (url.protocol === "https:" ? "443" : "80"), 10)
    };
  }
  const match = String(target || "").trim().match(/^([^:]+):(\d{1,5})$/);
  if (!match) {
    throw new HttpError(400, "invalid_target", `Expected host:port target, got "${target}"`);
  }
  return { host: match[1], port: Number.parseInt(match[2], 10) };
}
function isNodeStale(lastHeartbeatAt, expectedHeartbeatSec, now = Date.now()) {
  if (!lastHeartbeatAt) return true;
  const lastTs = Date.parse(lastHeartbeatAt);
  if (!Number.isFinite(lastTs)) return true;
  return now - lastTs > expectedHeartbeatSec * STALE_GRACE_MULTIPLIER * 1e3;
}
function buildDedupeKey(kind, id) {
  return `${kind}:${id}`;
}
function sha256Hex(value) {
  const data = new TextEncoder().encode(String(value));
  return crypto.subtle.digest("SHA-256", data).then((buffer) => {
    const bytes = new Uint8Array(buffer);
    return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  });
}
var HttpError = class extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.code = code;
  }
};
function okEnvelope(data) {
  return { ok: true, ...data };
}

// src/remediation.js
var APPROVAL_STATUS_SET = /* @__PURE__ */ new Set(["not_required", "pending", "approved", "rejected"]);
var RUNBOOK_SCOPE_SET = /* @__PURE__ */ new Set(["node", "channel", "project"]);
var ACTION_TYPE_SET = /* @__PURE__ */ new Set(["restart_service", "reload_service", "switch_upstream", "drain_node", "collect_diagnostics"]);
var POLICY_MODE_SET = /* @__PURE__ */ new Set(["suggest", "manual", "auto"]);
async function listRunbooks(env) {
  assertDb(env);
  const result = await env.DB.prepare(
    `SELECT id, slug, title, scope, action_type, params_schema_json, requires_approval_default, enabled, created_at, updated_at
     FROM runbooks
     ORDER BY slug`
  ).all();
  return result.results.map(deserializeRunbook);
}
async function upsertRunbook(env, body) {
  assertDb(env);
  const now = nowIso();
  const slug = normalizeSlug(body.slug || body.title, "runbook");
  const title = String(body.title || slug);
  const scope = String(body.scope || "").toLowerCase();
  const actionType = String(body.actionType || body.action_type || "").toLowerCase();
  if (!RUNBOOK_SCOPE_SET.has(scope)) {
    throw new HttpError(400, "invalid_scope", "runbook scope must be one of node, channel, project");
  }
  if (!ACTION_TYPE_SET.has(actionType)) {
    throw new HttpError(
      400,
      "invalid_action_type",
      "runbook action_type must be one of restart_service, reload_service, switch_upstream, drain_node, collect_diagnostics"
    );
  }
  const id = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO runbooks (
       id, slug, title, scope, action_type, params_schema_json, requires_approval_default, enabled, created_at, updated_at
     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
     ON CONFLICT(slug) DO UPDATE SET
       title = excluded.title,
       scope = excluded.scope,
       action_type = excluded.action_type,
       params_schema_json = excluded.params_schema_json,
       requires_approval_default = excluded.requires_approval_default,
       enabled = excluded.enabled,
       updated_at = excluded.updated_at`
  ).bind(
    id,
    slug,
    title,
    scope,
    actionType,
    JSON.stringify(body.paramsSchema || body.params_schema || {}),
    truthyInteger(body.requiresApprovalDefault, 1),
    truthyInteger(body.enabled, 1),
    now
  ).run();
  return getRunbookBySlug(env, slug);
}
async function listPolicies(env, projectSlug) {
  assertDb(env);
  const project = projectSlug ? await requireProject(env, projectSlug) : null;
  const statement = project ? env.DB.prepare(
    `SELECT rp.*, p.slug AS project_slug, rb.slug AS runbook_slug, rb.title AS runbook_title, rb.action_type, rb.scope
         FROM remediation_policies rp
         JOIN projects p ON p.id = rp.project_id
         JOIN runbooks rb ON rb.id = rp.runbook_id
         WHERE rp.project_id = ?1
         ORDER BY rp.created_at DESC`
  ).bind(project.id) : env.DB.prepare(
    `SELECT rp.*, p.slug AS project_slug, rb.slug AS runbook_slug, rb.title AS runbook_title, rb.action_type, rb.scope
         FROM remediation_policies rp
         JOIN projects p ON p.id = rp.project_id
         JOIN runbooks rb ON rb.id = rp.runbook_id
         ORDER BY rp.created_at DESC
         LIMIT 200`
  );
  const result = await statement.all();
  return result.results.map(deserializePolicy);
}
async function upsertPolicy(env, body) {
  assertDb(env);
  const project = await requireProject(env, body.projectSlug);
  const runbook = await resolveRunbook(env, body);
  const mode = String(body.mode || "").toLowerCase();
  if (!POLICY_MODE_SET.has(mode)) {
    throw new HttpError(400, "invalid_mode", "policy mode must be one of suggest, manual, auto");
  }
  const incidentKind = String(body.incidentKind || body.incident_kind || "").trim();
  if (!incidentKind) {
    throw new HttpError(400, "missing_incident_kind", "incidentKind is required");
  }
  const now = nowIso();
  const id = body.id || crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO remediation_policies (
       id, project_id, incident_kind, severity, runbook_id, mode, max_attempts, cooldown_sec,
       match_json, params_json, enabled, created_at, updated_at
     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12)
     ON CONFLICT(id) DO UPDATE SET
       incident_kind = excluded.incident_kind,
       severity = excluded.severity,
       runbook_id = excluded.runbook_id,
       mode = excluded.mode,
       max_attempts = excluded.max_attempts,
       cooldown_sec = excluded.cooldown_sec,
       match_json = excluded.match_json,
       params_json = excluded.params_json,
       enabled = excluded.enabled,
       updated_at = excluded.updated_at`
  ).bind(
    id,
    project.id,
    incidentKind,
    body.severity || null,
    runbook.id,
    mode,
    coerceInteger(body.maxAttempts, 1, 1, 20),
    coerceInteger(body.cooldownSec, 900, 0, 86400),
    JSON.stringify(body.match || {}),
    JSON.stringify(body.params || {}),
    truthyInteger(body.enabled, 1),
    now
  ).run();
  return getPolicyById(env, id);
}
async function listNodeCapabilities(env, projectSlug, nodeSlug = null) {
  assertDb(env);
  const project = await requireProject(env, projectSlug);
  const statement = nodeSlug ? env.DB.prepare(
    `SELECT nc.*, n.slug AS node_slug, p.slug AS project_slug
         FROM node_capabilities nc
         JOIN nodes n ON n.id = nc.node_id
         JOIN projects p ON p.id = n.project_id
         WHERE n.project_id = ?1 AND n.slug = ?2
         ORDER BY nc.action_type`
  ).bind(project.id, normalizeSlug(nodeSlug, "node")) : env.DB.prepare(
    `SELECT nc.*, n.slug AS node_slug, p.slug AS project_slug
         FROM node_capabilities nc
         JOIN nodes n ON n.id = nc.node_id
         JOIN projects p ON p.id = n.project_id
         WHERE n.project_id = ?1
         ORDER BY n.slug, nc.action_type`
  ).bind(project.id);
  const result = await statement.all();
  return result.results.map(deserializeNodeCapability);
}
async function upsertNodeCapability(env, body) {
  assertDb(env);
  const project = await requireProject(env, body.projectSlug);
  const node = await requireNode(env, project.id, body.nodeSlug);
  const actionType = String(body.actionType || body.action_type || "").toLowerCase();
  if (!ACTION_TYPE_SET.has(actionType)) {
    throw new HttpError(400, "invalid_action_type", "node capability action_type is invalid");
  }
  const now = nowIso();
  const id = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO node_capabilities (
       id, node_id, action_type, enabled, config_json, created_at, updated_at
     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
     ON CONFLICT(node_id, action_type) DO UPDATE SET
       enabled = excluded.enabled,
       config_json = excluded.config_json,
       updated_at = excluded.updated_at`
  ).bind(id, node.id, actionType, truthyInteger(body.enabled, 1), JSON.stringify(body.config || {}), now).run();
  const result = await env.DB.prepare(
    `SELECT nc.*, n.slug AS node_slug, p.slug AS project_slug
     FROM node_capabilities nc
     JOIN nodes n ON n.id = nc.node_id
     JOIN projects p ON p.id = n.project_id
     WHERE nc.node_id = ?1 AND nc.action_type = ?2`
  ).bind(node.id, actionType).first();
  return deserializeNodeCapability(result);
}
async function listActions(env, filters = {}) {
  assertDb(env);
  const clauses = [];
  const bindings = [];
  let index = 1;
  if (filters.projectSlug) {
    const project = await requireProject(env, filters.projectSlug);
    clauses.push(`ra.project_id = ?${index}`);
    bindings.push(project.id);
    index += 1;
  }
  if (filters.status) {
    clauses.push(`ra.status = ?${index}`);
    bindings.push(filters.status);
    index += 1;
  }
  if (filters.incidentId) {
    clauses.push(`ra.incident_id = ?${index}`);
    bindings.push(filters.incidentId);
    index += 1;
  }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const result = await env.DB.prepare(
    `SELECT ra.*, p.slug AS project_slug, n.slug AS node_slug, c.slug AS channel_slug,
            rb.slug AS runbook_slug, rb.title AS runbook_title, rb.action_type, rb.scope
     FROM remediation_actions ra
     JOIN projects p ON p.id = ra.project_id
     JOIN runbooks rb ON rb.id = ra.runbook_id
     LEFT JOIN nodes n ON n.id = ra.node_id
     LEFT JOIN channels c ON c.id = ra.channel_id
     ${where}
     ORDER BY CASE ra.status WHEN 'queued' THEN 0 WHEN 'leased' THEN 1 WHEN 'running' THEN 2 ELSE 3 END, ra.created_at DESC
     LIMIT 200`
  ).bind(...bindings).all();
  return result.results.map(deserializeAction);
}
async function listActionEvents(env, actionId) {
  assertDb(env);
  await requireAction(env, actionId);
  const result = await env.DB.prepare(
    `SELECT id, action_id, kind, payload_json, created_at
     FROM remediation_action_events
     WHERE action_id = ?1
     ORDER BY created_at ASC`
  ).bind(actionId).all();
  return result.results.map((row) => ({
    ...row,
    payload: safeJsonParse(row.payload_json, {})
  }));
}
async function planIncidentRemediation(env, incidentId) {
  assertDb(env);
  const incident = await requireIncident(env, incidentId);
  const matches = await matchPoliciesForIncident(env, incident);
  const actions = await listActions(env, { incidentId });
  return {
    incident: serializeIncidentContext(incident),
    matches: matches.map((item) => ({
      policy: deserializePolicy(item.policy),
      runbook: deserializeRunbook(item.runbook),
      capability: item.capability ? deserializeNodeCapability(item.capability) : null,
      effectiveParams: item.effectiveParams,
      autoCreatable: item.autoCreatable
    })),
    activeActions: actions.filter((action) => ["pending", "queued", "leased", "running"].includes(action.status)),
    recommendation: buildRemediationRecommendation(incident, matches)
  };
}
async function createIncidentRemediationAction(env, incidentId, body) {
  assertDb(env);
  const incident = await requireIncident(env, incidentId);
  const creation = await prepareActionCreation(env, incident, body);
  return createRemediationActionRecord(env, creation);
}
async function approveRemediationAction(env, actionId, body = {}) {
  assertDb(env);
  const action = await requireAction(env, actionId);
  if (["succeeded", "failed", "canceled", "expired"].includes(action.status)) {
    throw new HttpError(409, "action_finalized", "Action is already finalized");
  }
  const decision = String(body.decision || "approve").toLowerCase();
  if (decision !== "approve" && decision !== "reject") {
    throw new HttpError(400, "invalid_decision", "decision must be approve or reject");
  }
  const now = nowIso();
  if (decision === "approve") {
    await env.DB.prepare(
      `UPDATE remediation_actions
       SET approval_status = 'approved', status = CASE WHEN status = 'pending' THEN 'queued' ELSE status END, updated_at = ?1
       WHERE id = ?2`
    ).bind(now, actionId).run();
    await appendActionEvent(env, actionId, "approved", {
      by: body.by || "admin",
      note: body.note || null
    });
  } else {
    await env.DB.prepare(
      `UPDATE remediation_actions
       SET approval_status = 'rejected', status = 'canceled', finished_at = ?1, updated_at = ?1
       WHERE id = ?2`
    ).bind(now, actionId).run();
    await appendActionEvent(env, actionId, "rejected", {
      by: body.by || "admin",
      note: body.note || null
    });
  }
  return requireAction(env, actionId);
}
async function cancelRemediationAction(env, actionId, body = {}) {
  assertDb(env);
  await requireAction(env, actionId);
  const now = nowIso();
  await env.DB.prepare(
    `UPDATE remediation_actions
     SET status = 'canceled', finished_at = ?1, updated_at = ?1
     WHERE id = ?2 AND status NOT IN ('succeeded', 'failed', 'canceled', 'expired')`
  ).bind(now, actionId).run();
  await appendActionEvent(env, actionId, "canceled", {
    by: body.by || "admin",
    reason: body.reason || "canceled_by_admin"
  });
  return requireAction(env, actionId);
}
async function pullAgentActions(env, token, body) {
  assertDb(env);
  const project = await requireProject(env, body.projectSlug || token.project_slug);
  if (project.id !== token.project_id) {
    throw new HttpError(403, "project_mismatch", "Agent token does not belong to this project");
  }
  const node = await requireNode(env, project.id, body.nodeSlug || body.node?.slug);
  const limit = coerceInteger(body.limit, 1, 1, 5);
  await expireLeases(env);
  const result = await env.DB.prepare(
    `SELECT ra.id
     FROM remediation_actions ra
     JOIN runbooks rb ON rb.id = ra.runbook_id
     WHERE ra.project_id = ?1
       AND (ra.node_id IS NULL OR ra.node_id = ?2)
       AND ra.status = 'queued'
       AND ra.approval_status IN ('approved', 'not_required')
       AND rb.enabled = 1
     ORDER BY ra.created_at ASC
     LIMIT ?3`
  ).bind(project.id, node.id, limit).all();
  const leased = [];
  for (const row of result.results) {
    const leaseToken = crypto.randomUUID();
    const now = nowIso();
    const leaseExpiresAt = nowIso(Date.now() + coerceInteger(body.leaseSec, 120, 30, 900) * 1e3);
    const update = await env.DB.prepare(
      `UPDATE remediation_actions
       SET status = 'leased', lease_token = ?1, lease_expires_at = ?2, updated_at = ?3
       WHERE id = ?4 AND status = 'queued'`
    ).bind(leaseToken, leaseExpiresAt, now, row.id).run();
    if (!update.meta?.changes) {
      continue;
    }
    await appendActionEvent(env, row.id, "leased", {
      nodeSlug: node.slug,
      leaseExpiresAt
    });
    const action = await requireAction(env, row.id);
    leased.push({
      ...action,
      leaseToken
    });
  }
  return {
    node: node.slug,
    actions: leased
  };
}
async function submitActionResult(env, token, actionId, body) {
  assertDb(env);
  const action = await requireAction(env, actionId);
  if (action.project_id !== token.project_id) {
    throw new HttpError(403, "project_mismatch", "Action does not belong to this agent project");
  }
  if (!body.leaseToken || body.leaseToken !== action.lease_token) {
    throw new HttpError(409, "invalid_lease_token", "leaseToken is required and must match the leased action");
  }
  if (!["leased", "running"].includes(action.status)) {
    throw new HttpError(409, "action_not_leased", "Action is not currently leased");
  }
  const resultStatus = String(body.status || "").toLowerCase();
  if (!["running", "succeeded", "failed", "canceled"].includes(resultStatus)) {
    throw new HttpError(400, "invalid_action_status", "status must be running, succeeded, failed, or canceled");
  }
  const now = nowIso();
  if (resultStatus === "running") {
    await env.DB.prepare(
      `UPDATE remediation_actions
       SET status = 'running', started_at = COALESCE(started_at, ?1), updated_at = ?1
       WHERE id = ?2`
    ).bind(now, actionId).run();
    await appendActionEvent(env, actionId, "started", {
      summary: body.summary || null,
      result: body.result || {}
    });
    return requireAction(env, actionId);
  }
  const verify = await verifyRemediationAction(env, action, resultStatus, body);
  await env.DB.prepare(
    `UPDATE remediation_actions
     SET status = ?1,
         started_at = COALESCE(started_at, ?2),
         finished_at = ?2,
         result_summary = ?3,
         result_json = ?4,
         verify_status = ?5,
         lease_token = NULL,
         lease_expires_at = NULL,
         updated_at = ?2
     WHERE id = ?6`
  ).bind(
    resultStatus,
    now,
    body.summary || null,
    JSON.stringify(body.result || {}),
    verify.verifyStatus,
    actionId
  ).run();
  await appendActionEvent(env, actionId, "result", {
    status: resultStatus,
    summary: body.summary || null,
    result: body.result || {}
  });
  await appendActionEvent(env, actionId, "verified", verify.eventPayload);
  if (verify.resolveIncidentId) {
    await env.DB.prepare(
      `UPDATE incidents
       SET status = 'resolved', resolved_at = ?1, last_seen_at = ?1, updated_at = ?1
       WHERE id = ?2 AND status = 'open'`
    ).bind(now, verify.resolveIncidentId).run();
  }
  return requireAction(env, actionId);
}
async function scheduleIncidentRemediation(env, incidentId) {
  assertDb(env);
  const incident = await requireIncident(env, incidentId);
  const matches = await matchPoliciesForIncident(env, incident);
  const created = [];
  for (const item of matches) {
    const policy = deserializePolicy(item.policy);
    const runbook = deserializeRunbook(item.runbook);
    if (policy.mode === "suggest") {
      await appendIncidentEvent(env, incident.id, "remediation_suggested", {
        policyId: policy.id,
        runbook: runbook.slug,
        actionType: runbook.actionType
      });
      continue;
    }
    if (policy.mode === "auto" && !item.autoCreatable) {
      await appendIncidentEvent(env, incident.id, "remediation_skipped", {
        policyId: policy.id,
        reason: "auto_policy_not_creatable",
        runbook: runbook.slug
      });
      continue;
    }
    const duplicate = await findActiveActionForIncidentRunbook(env, incident.id, runbook.id);
    if (duplicate) {
      continue;
    }
    const coolingDown = await policyInCooldown(env, incident, runbook.id, policy.cooldownSec);
    if (coolingDown) {
      await appendIncidentEvent(env, incident.id, "remediation_skipped", {
        policyId: policy.id,
        reason: "cooldown_active",
        runbook: runbook.slug,
        cooldownSec: policy.cooldownSec
      });
      continue;
    }
    const attemptNo = await countActionsForIncidentRunbook(env, incident.id, runbook.id) + 1;
    if (attemptNo > policy.maxAttempts) {
      continue;
    }
    const approvalStatus = policy.mode === "manual" ? "pending" : runbook.requiresApprovalDefault ? "pending" : "not_required";
    const status = approvalStatus === "not_required" ? "queued" : "pending";
    const action = await createRemediationActionRecord(env, {
      incident,
      runbook,
      policy,
      source: "policy",
      approvalStatus,
      status,
      params: item.effectiveParams,
      attemptNo,
      resultSummary: null,
      nodeId: incident.node_id || null,
      channelId: incident.channel_id || null
    });
    created.push(action);
  }
  return created;
}
function assertDb(env) {
  if (!env.DB || typeof env.DB.prepare !== "function") {
    throw new HttpError(500, "missing_db", "D1 binding DB is not configured");
  }
}
async function prepareActionCreation(env, incident, body) {
  const runbook = await resolveRunbook(env, body);
  const policy = body.policyId ? await requirePolicy(env, body.policyId) : null;
  const attemptNo = await countActionsForIncidentRunbook(env, incident.id, runbook.id) + 1;
  const approvalStatus = normalizeApprovalStatus(
    body.approvalStatus,
    body.approved === true ? "approved" : runbook.requiresApprovalDefault ? "pending" : "not_required"
  );
  const status = approvalStatus === "approved" || approvalStatus === "not_required" ? "queued" : "pending";
  const params = {
    ...policy ? safeJsonParse(policy.params_json, {}) : {},
    ...body.params || {}
  };
  return {
    incident,
    runbook,
    policy: policy ? deserializePolicy(policy) : null,
    source: body.source || "admin",
    approvalStatus,
    status,
    params,
    attemptNo,
    resultSummary: null,
    nodeId: incident.node_id || null,
    channelId: incident.channel_id || null
  };
}
async function createRemediationActionRecord(env, creation) {
  const now = nowIso();
  const id = crypto.randomUUID();
  const runbookId = creation.runbook.id || creation.runbook.runbook_id;
  await env.DB.prepare(
    `INSERT INTO remediation_actions (
       id, incident_id, project_id, node_id, channel_id, runbook_id, source, approval_status, status,
       params_json, attempt_no, verify_status, created_at, updated_at
     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'pending', ?12, ?12)`
  ).bind(
    id,
    creation.incident.id,
    creation.incident.project_id,
    creation.nodeId,
    creation.channelId,
    runbookId,
    creation.source,
    creation.approvalStatus,
    creation.status,
    JSON.stringify(creation.params || {}),
    creation.attemptNo || 1,
    now
  ).run();
  await appendActionEvent(env, id, "queued", {
    source: creation.source,
    approvalStatus: creation.approvalStatus,
    status: creation.status,
    policyId: creation.policy?.id || null,
    params: creation.params || {}
  });
  await appendIncidentEvent(env, creation.incident.id, "remediation_action_created", {
    actionId: id,
    runbookId,
    source: creation.source
  });
  return requireAction(env, id);
}
async function verifyRemediationAction(env, action, resultStatus, body) {
  if (resultStatus !== "succeeded") {
    return {
      verifyStatus: "failed",
      eventPayload: {
        verifyStatus: "failed",
        reason: body.summary || "action_failed"
      },
      resolveIncidentId: null
    };
  }
  if (!action.channel_id) {
    return {
      verifyStatus: "pending",
      eventPayload: {
        verifyStatus: "pending",
        reason: "awaiting_next_heartbeat"
      },
      resolveIncidentId: null
    };
  }
  const channel = await env.DB.prepare(
    `SELECT id, project_id, protocol, target, timeout_ms, expected_statuses_json
     FROM channels
     WHERE id = ?1`
  ).bind(action.channel_id).first();
  if (!channel || !["http", "https", "head"].includes(channel.protocol)) {
    return {
      verifyStatus: "skipped",
      eventPayload: {
        verifyStatus: "skipped",
        reason: "channel_verification_not_supported"
      },
      resolveIncidentId: null
    };
  }
  const check = await executeChannelVerification(channel);
  return {
    verifyStatus: check.status === "pass" ? "passed" : "failed",
    eventPayload: {
      verifyStatus: check.status === "pass" ? "passed" : "failed",
      observedAt: check.observedAt,
      latencyMs: check.latencyMs,
      error: check.error
    },
    resolveIncidentId: check.status === "pass" ? action.incident_id : null
  };
}
async function executeChannelVerification(channel) {
  const protocol = channel.protocol === "head" ? "https" : channel.protocol;
  const timeoutMs = channel.timeout_ms || DEFAULT_HTTP_TIMEOUT_MS;
  const observedAt = nowIso();
  const startedAt = Date.now();
  try {
    const { url } = parseTarget(channel.target, protocol);
    const method = channel.protocol === "head" ? "HEAD" : "GET";
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    const response = await fetch(url.toString(), {
      method,
      redirect: "manual",
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    const allowed = expectedHttpStatuses(safeJsonParse(channel.expected_statuses_json, []));
    const passed = allowed.includes(response.status);
    return {
      status: passed ? "pass" : "fail",
      observedAt,
      latencyMs: Date.now() - startedAt,
      error: passed ? null : `Unexpected HTTP status ${response.status}`
    };
  } catch (error) {
    return {
      status: "fail",
      observedAt,
      latencyMs: Date.now() - startedAt,
      error: error?.message || "Verification failed"
    };
  }
}
async function matchPoliciesForIncident(env, incident) {
  const result = await env.DB.prepare(
    `SELECT rp.*, rb.id AS runbook_id, rb.slug AS runbook_slug, rb.title AS runbook_title, rb.scope, rb.action_type,
            rb.params_schema_json, rb.requires_approval_default, rb.enabled AS runbook_enabled
     FROM remediation_policies rp
     JOIN runbooks rb ON rb.id = rp.runbook_id
     WHERE rp.project_id = ?1
       AND rp.incident_kind = ?2
       AND rp.enabled = 1
       AND rb.enabled = 1`
  ).bind(incident.project_id, incident.kind).all();
  const matches = [];
  for (const row of result.results) {
    const policy = row;
    const matchJson = safeJsonParse(policy.match_json, {});
    if (policy.severity && policy.severity !== incident.severity) {
      continue;
    }
    if (!incidentMatches(policy, incident, matchJson)) {
      continue;
    }
    const capability = incident.node_id ? await findNodeCapability(env, incident.node_id, row.action_type) : null;
    const effectiveParams = {
      ...safeJsonParse(policy.params_json, {})
    };
    matches.push({
      policy,
      runbook: row,
      capability,
      effectiveParams,
      autoCreatable: policy.mode === "auto" && (!row.requires_approval_default || row.requires_approval_default === 0) && (!!capability || row.scope === "project")
    });
  }
  return matches;
}
function incidentMatches(policy, incident, matchJson) {
  if (matchJson.channelSlug && matchJson.channelSlug !== incident.channel_slug) {
    return false;
  }
  if (matchJson.nodeSlug && matchJson.nodeSlug !== incident.node_slug) {
    return false;
  }
  if (matchJson.protocol && matchJson.protocol !== incident.channel_protocol) {
    return false;
  }
  if (matchJson.region && matchJson.region !== incident.node_region) {
    return false;
  }
  return true;
}
function buildRemediationRecommendation(incident, matches) {
  if (matches.length === 0) {
    return {
      action: null,
      reason: "No matching remediation policy",
      source: incident.ai_summary ? "incident_ai_summary" : "policy_engine",
      aiSummary: incident.ai_summary || null
    };
  }
  const candidate = matches[0];
  return {
    action: candidate.runbook.action_type,
    runbook: candidate.runbook.runbook_slug,
    reason: `${candidate.policy.mode} policy matched incident ${incident.kind}`,
    source: incident.ai_summary ? "policy_engine+incident_ai_summary" : "policy_engine",
    aiSummary: incident.ai_summary || null
  };
}
async function resolveRunbook(env, body) {
  if (body.runbookId) {
    const row = await env.DB.prepare(
      `SELECT id, slug, title, scope, action_type, params_schema_json, requires_approval_default, enabled, created_at, updated_at
       FROM runbooks WHERE id = ?1`
    ).bind(body.runbookId).first();
    if (!row) {
      throw new HttpError(404, "runbook_not_found", `Runbook "${body.runbookId}" was not found`);
    }
    return deserializeRunbook(row);
  }
  if (body.runbookSlug) {
    const row = await getRunbookBySlug(env, normalizeSlug(body.runbookSlug, "runbook"));
    if (!row) {
      throw new HttpError(404, "runbook_not_found", `Runbook "${body.runbookSlug}" was not found`);
    }
    return row;
  }
  if (body.policyId) {
    const policy = await requirePolicy(env, body.policyId);
    return resolveRunbook(env, { runbookId: policy.runbook_id });
  }
  throw new HttpError(400, "missing_runbook", "runbookId, runbookSlug, or policyId is required");
}
async function getRunbookBySlug(env, slug) {
  const row = await env.DB.prepare(
    `SELECT id, slug, title, scope, action_type, params_schema_json, requires_approval_default, enabled, created_at, updated_at
     FROM runbooks WHERE slug = ?1`
  ).bind(slug).first();
  return row ? deserializeRunbook(row) : null;
}
async function getPolicyById(env, id) {
  const row = await env.DB.prepare(
    `SELECT rp.*, p.slug AS project_slug, rb.slug AS runbook_slug, rb.title AS runbook_title, rb.action_type, rb.scope
     FROM remediation_policies rp
     JOIN projects p ON p.id = rp.project_id
     JOIN runbooks rb ON rb.id = rp.runbook_id
     WHERE rp.id = ?1`
  ).bind(id).first();
  if (!row) {
    throw new HttpError(404, "policy_not_found", `Policy "${id}" was not found`);
  }
  return deserializePolicy(row);
}
async function requirePolicy(env, id) {
  const row = await env.DB.prepare(
    `SELECT * FROM remediation_policies WHERE id = ?1`
  ).bind(id).first();
  if (!row) {
    throw new HttpError(404, "policy_not_found", `Policy "${id}" was not found`);
  }
  return row;
}
async function requireAction(env, id) {
  const row = await env.DB.prepare(
    `SELECT ra.*, p.slug AS project_slug, n.slug AS node_slug, c.slug AS channel_slug,
            rb.slug AS runbook_slug, rb.title AS runbook_title, rb.action_type, rb.scope
     FROM remediation_actions ra
     JOIN projects p ON p.id = ra.project_id
     JOIN runbooks rb ON rb.id = ra.runbook_id
     LEFT JOIN nodes n ON n.id = ra.node_id
     LEFT JOIN channels c ON c.id = ra.channel_id
     WHERE ra.id = ?1`
  ).bind(id).first();
  if (!row) {
    throw new HttpError(404, "action_not_found", `Action "${id}" was not found`);
  }
  return deserializeAction(row);
}
async function requireIncident(env, id) {
  const row = await env.DB.prepare(
    `SELECT i.*, p.slug AS project_slug, n.slug AS node_slug, n.region AS node_region,
            c.slug AS channel_slug, c.protocol AS channel_protocol, c.target AS channel_target
     FROM incidents i
     JOIN projects p ON p.id = i.project_id
     LEFT JOIN nodes n ON n.id = i.node_id
     LEFT JOIN channels c ON c.id = i.channel_id
     WHERE i.id = ?1`
  ).bind(id).first();
  if (!row) {
    throw new HttpError(404, "incident_not_found", `Incident "${id}" was not found`);
  }
  return row;
}
async function requireProject(env, projectSlug) {
  const project = await env.DB.prepare(
    "SELECT id, slug, name, public_status_token FROM projects WHERE slug = ?1"
  ).bind(projectSlug).first();
  if (!project) {
    throw new HttpError(404, "project_not_found", `Project "${projectSlug}" was not found`);
  }
  return project;
}
async function requireNode(env, projectId, nodeSlug) {
  const slug = normalizeSlug(nodeSlug, "node");
  const node = await env.DB.prepare(
    `SELECT * FROM nodes WHERE project_id = ?1 AND slug = ?2`
  ).bind(projectId, slug).first();
  if (!node) {
    throw new HttpError(404, "node_not_found", `Node "${slug}" was not found`);
  }
  return node;
}
async function findNodeCapability(env, nodeId, actionType) {
  const row = await env.DB.prepare(
    `SELECT nc.*, n.slug AS node_slug, p.slug AS project_slug
     FROM node_capabilities nc
     JOIN nodes n ON n.id = nc.node_id
     JOIN projects p ON p.id = n.project_id
     WHERE nc.node_id = ?1 AND nc.action_type = ?2 AND nc.enabled = 1`
  ).bind(nodeId, actionType).first();
  return row || null;
}
async function findActiveActionForIncidentRunbook(env, incidentId, runbookId) {
  return env.DB.prepare(
    `SELECT id
     FROM remediation_actions
     WHERE incident_id = ?1
       AND runbook_id = ?2
       AND status IN ('pending', 'queued', 'leased', 'running')
     LIMIT 1`
  ).bind(incidentId, runbookId).first();
}
async function countActionsForIncidentRunbook(env, incidentId, runbookId) {
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS count
     FROM remediation_actions
     WHERE incident_id = ?1 AND runbook_id = ?2`
  ).bind(incidentId, runbookId).first();
  return Number(row?.count || 0);
}
async function policyInCooldown(env, incident, runbookId, cooldownSec) {
  if (!cooldownSec || cooldownSec <= 0) {
    return false;
  }
  const row = await env.DB.prepare(
    `SELECT finished_at, created_at
     FROM remediation_actions
     WHERE project_id = ?1
       AND runbook_id = ?2
       AND (
         (node_id IS NULL AND ?3 IS NULL) OR node_id = ?3
       )
       AND (
         (channel_id IS NULL AND ?4 IS NULL) OR channel_id = ?4
       )
       AND status IN ('succeeded', 'failed', 'canceled', 'expired', 'pending', 'queued', 'leased', 'running')
     ORDER BY COALESCE(finished_at, created_at) DESC
     LIMIT 1`
  ).bind(incident.project_id, runbookId, incident.node_id || null, incident.channel_id || null).first();
  if (!row) {
    return false;
  }
  const ts = Date.parse(row.finished_at || row.created_at || "");
  if (!Number.isFinite(ts)) {
    return false;
  }
  return Date.now() - ts < cooldownSec * 1e3;
}
async function appendActionEvent(env, actionId, kind, payload) {
  await env.DB.prepare(
    `INSERT INTO remediation_action_events (id, action_id, kind, payload_json, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5)`
  ).bind(crypto.randomUUID(), actionId, kind, JSON.stringify(payload || {}), nowIso()).run();
}
async function appendIncidentEvent(env, incidentId, kind, payload) {
  await env.DB.prepare(
    `INSERT INTO incident_events (id, incident_id, kind, payload_json, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5)`
  ).bind(crypto.randomUUID(), incidentId, kind, JSON.stringify(payload || {}), nowIso()).run();
}
async function expireLeases(env) {
  await env.DB.prepare(
    `UPDATE remediation_actions
     SET status = 'expired', lease_token = NULL, lease_expires_at = NULL, updated_at = ?1
     WHERE status IN ('leased', 'running')
       AND lease_expires_at IS NOT NULL
       AND lease_expires_at < ?1`
  ).bind(nowIso()).run();
}
function deserializeRunbook(row) {
  return {
    id: row.id,
    slug: row.slug,
    title: row.title,
    scope: row.scope,
    actionType: row.action_type,
    paramsSchema: safeJsonParse(row.params_schema_json, {}),
    requiresApprovalDefault: !!row.requires_approval_default,
    enabled: !!row.enabled,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}
function deserializePolicy(row) {
  return {
    id: row.id,
    projectId: row.project_id,
    projectSlug: row.project_slug,
    incidentKind: row.incident_kind,
    severity: row.severity,
    runbookId: row.runbook_id,
    runbookSlug: row.runbook_slug,
    runbookTitle: row.runbook_title,
    actionType: row.action_type,
    scope: row.scope,
    mode: row.mode,
    maxAttempts: row.max_attempts,
    cooldownSec: row.cooldown_sec,
    match: safeJsonParse(row.match_json, {}),
    params: safeJsonParse(row.params_json, {}),
    enabled: !!row.enabled,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}
function deserializeNodeCapability(row) {
  return {
    id: row.id,
    nodeId: row.node_id,
    nodeSlug: row.node_slug,
    projectSlug: row.project_slug,
    actionType: row.action_type,
    enabled: !!row.enabled,
    config: safeJsonParse(row.config_json, {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}
function deserializeAction(row) {
  return {
    id: row.id,
    incidentId: row.incident_id,
    projectId: row.project_id,
    projectSlug: row.project_slug,
    nodeId: row.node_id,
    nodeSlug: row.node_slug,
    channelId: row.channel_id,
    channelSlug: row.channel_slug,
    runbookId: row.runbook_id,
    runbookSlug: row.runbook_slug,
    runbookTitle: row.runbook_title,
    actionType: row.action_type,
    scope: row.scope,
    source: row.source,
    approvalStatus: row.approval_status,
    status: row.status,
    leaseToken: row.lease_token || null,
    leaseExpiresAt: row.lease_expires_at,
    params: safeJsonParse(row.params_json, {}),
    attemptNo: row.attempt_no,
    startedAt: row.started_at,
    finishedAt: row.finished_at,
    resultSummary: row.result_summary,
    result: safeJsonParse(row.result_json, null),
    verifyStatus: row.verify_status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    project_id: row.project_id,
    node_id: row.node_id,
    channel_id: row.channel_id,
    lease_token: row.lease_token
  };
}
function serializeIncidentContext(row) {
  return {
    id: row.id,
    projectId: row.project_id,
    projectSlug: row.project_slug,
    nodeId: row.node_id,
    nodeSlug: row.node_slug,
    channelId: row.channel_id,
    channelSlug: row.channel_slug,
    kind: row.kind,
    severity: row.severity,
    status: row.status,
    title: row.title,
    summary: row.summary,
    aiSummary: row.ai_summary,
    nodeRegion: row.node_region,
    channelProtocol: row.channel_protocol,
    channelTarget: row.channel_target,
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
    resolvedAt: row.resolved_at
  };
}
function normalizeApprovalStatus(value, fallback) {
  const normalized = String(value || fallback || "").toLowerCase();
  if (!APPROVAL_STATUS_SET.has(normalized)) {
    throw new HttpError(400, "invalid_approval_status", "approvalStatus is invalid");
  }
  return normalized;
}
function truthyInteger(value, fallback) {
  if (value === void 0 || value === null || value === "") return fallback;
  return value ? 1 : 0;
}
function safeJsonParse(value, fallback = null) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

// src/index.js
var AI_DEFAULT_MODEL = "@cf/meta/llama-3.1-8b-instruct";
var index_default = {
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
  }
};
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  if (request.method === "GET" && path === "/") {
    return json(
      okEnvelope({
        service: "proxy-reliability-control-plane",
        version: "0.1.0",
        time: nowIso()
      })
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
  if (request.method === "GET" && path.startsWith("/v1/admin/incidents/") && path.endsWith("/events")) {
    await requireAdmin(request, env);
    const incidentId = path.split("/")[4];
    const result = await listIncidentEvents(env, incidentId);
    return json(okEnvelope({ incidentId, events: result }));
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
  if (request.method === "POST" && path.startsWith("/v1/admin/incidents/") && path.endsWith("/remediation/plan")) {
    await requireAdmin(request, env);
    const incidentId = path.split("/")[4];
    const result = await planIncidentRemediation(env, incidentId);
    return json(okEnvelope(result));
  }
  if (request.method === "POST" && path.startsWith("/v1/admin/incidents/") && path.endsWith("/remediation/actions")) {
    await requireAdmin(request, env);
    const incidentId = path.split("/")[4];
    const body = await readJson(request);
    const result = await createIncidentRemediationAction(env, incidentId, body);
    return json(okEnvelope(result), { status: 201 });
  }
  if (request.method === "GET" && path === "/v1/admin/runbooks") {
    await requireAdmin(request, env);
    const result = await listRunbooks(env);
    return json(okEnvelope({ runbooks: result }));
  }
  if (request.method === "POST" && path === "/v1/admin/runbooks") {
    await requireAdmin(request, env);
    const body = await readJson(request);
    const result = await upsertRunbook(env, body);
    return json(okEnvelope(result), { status: 201 });
  }
  if (request.method === "GET" && path === "/v1/admin/policies") {
    await requireAdmin(request, env);
    const result = await listPolicies(env, url.searchParams.get("project"));
    return json(okEnvelope({ policies: result }));
  }
  if (request.method === "POST" && path === "/v1/admin/policies") {
    await requireAdmin(request, env);
    const body = await readJson(request);
    const result = await upsertPolicy(env, body);
    return json(okEnvelope(result), { status: 201 });
  }
  if (request.method === "GET" && path === "/v1/admin/node-capabilities") {
    await requireAdmin(request, env);
    const result = await listNodeCapabilities(
      env,
      url.searchParams.get("project"),
      url.searchParams.get("node")
    );
    return json(okEnvelope({ capabilities: result }));
  }
  if (request.method === "POST" && path === "/v1/admin/node-capabilities") {
    await requireAdmin(request, env);
    const body = await readJson(request);
    const result = await upsertNodeCapability(env, body);
    return json(okEnvelope(result), { status: 201 });
  }
  if (request.method === "GET" && path === "/v1/admin/actions") {
    await requireAdmin(request, env);
    const result = await listActions(env, {
      projectSlug: url.searchParams.get("project"),
      status: url.searchParams.get("status"),
      incidentId: url.searchParams.get("incidentId")
    });
    return json(okEnvelope({ actions: result }));
  }
  if (request.method === "GET" && path.startsWith("/v1/admin/actions/") && path.endsWith("/events")) {
    await requireAdmin(request, env);
    const actionId = path.split("/")[4];
    const result = await listActionEvents(env, actionId);
    return json(okEnvelope({ actionId, events: result }));
  }
  if (request.method === "POST" && path.startsWith("/v1/admin/actions/") && path.endsWith("/approve")) {
    await requireAdmin(request, env);
    const actionId = path.split("/")[4];
    const body = request.headers.get("content-length") === "0" ? {} : await readOptionalJson(request);
    const result = await approveRemediationAction(env, actionId, body);
    return json(okEnvelope(result));
  }
  if (request.method === "POST" && path.startsWith("/v1/admin/actions/") && path.endsWith("/cancel")) {
    await requireAdmin(request, env);
    const actionId = path.split("/")[4];
    const body = request.headers.get("content-length") === "0" ? {} : await readOptionalJson(request);
    const result = await cancelRemediationAction(env, actionId, body);
    return json(okEnvelope(result));
  }
  if (request.method === "GET" && path === "/v1/admin/agent-tokens") {
    await requireAdmin(request, env);
    const projectSlug = url.searchParams.get("project");
    const result = await listAgentTokens(env, projectSlug);
    return json(okEnvelope({ tokens: result }));
  }
  if (request.method === "POST" && path === "/v1/admin/agent-tokens") {
    await requireAdmin(request, env);
    const body = await readJson(request);
    const result = await issueAgentToken(env, body);
    return json(okEnvelope(result), { status: 201 });
  }
  if (request.method === "POST" && path.startsWith("/v1/admin/agent-tokens/") && path.endsWith("/revoke")) {
    await requireAdmin(request, env);
    const tokenId = path.split("/")[4];
    const result = await revokeAgentToken(env, tokenId);
    return json(okEnvelope(result));
  }
  if (request.method === "POST" && path === "/v1/admin/sweeps/run") {
    await requireAdmin(request, env);
    const body = request.headers.get("content-length") === "0" ? {} : await readOptionalJson(request);
    const result = await runScheduledSweep(env, Date.now(), { projectSlug: body.projectSlug || null });
    return json(okEnvelope(result));
  }
  if (request.method === "POST" && path === "/v1/agent/heartbeat") {
    const token = await requireAgent(request, env);
    const body = await readJson(request);
    const result = await ingestHeartbeat(env, token, body, request);
    return json(okEnvelope(result), { status: 202 });
  }
  if (request.method === "POST" && path === "/v1/agent/pull-actions") {
    const token = await requireAgent(request, env);
    const body = request.headers.get("content-length") === "0" ? {} : await readOptionalJson(request);
    const result = await pullAgentActions(env, token, body);
    return json(okEnvelope(result));
  }
  if (request.method === "POST" && path.startsWith("/v1/agent/actions/") && path.endsWith("/result")) {
    const token = await requireAgent(request, env);
    const actionId = path.split("/")[4];
    const body = await readJson(request);
    const result = await submitActionResult(env, token, actionId, body);
    return json(okEnvelope(result));
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
     WHERE at.token_hash = ?1 AND at.revoked_at IS NULL`
  ).bind(hash).first();
  if (!row) {
    throw new HttpError(401, "unauthorized", "Agent token is invalid");
  }
  await env.DB.prepare("UPDATE agent_tokens SET last_used_at = ?1 WHERE id = ?2").bind(nowIso(), row.id).run();
  return row;
}
async function readOptionalJson(request) {
  if ((request.headers.get("content-length") || "") === "0") {
    return {};
  }
  const text = await request.text();
  if (!text.trim()) {
    return {};
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, "invalid_json", "Body must contain valid JSON");
  }
}
function bearerToken(request) {
  const header = request.headers.get("authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}
async function bootstrapProject(env, body) {
  assertDb2(env);
  const tenantSlug = normalizeSlug(body?.tenant?.slug || body?.tenantSlug, "tenant");
  const tenantName = String(body?.tenant?.name || body?.tenantName || tenantSlug);
  const projectSlug = normalizeSlug(body?.project?.slug || body?.projectSlug, "project");
  const projectName = String(body?.project?.name || body?.projectName || projectSlug);
  const now = nowIso();
  const tenantId = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO tenants (id, slug, name, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?4)
     ON CONFLICT(slug) DO UPDATE SET name = excluded.name, updated_at = excluded.updated_at`
  ).bind(tenantId, tenantSlug, tenantName, now).run();
  const tenant = await env.DB.prepare("SELECT id, slug, name FROM tenants WHERE slug = ?1").bind(tenantSlug).first();
  const projectId = crypto.randomUUID();
  const publicStatusToken = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO projects (id, tenant_id, slug, name, public_status_token, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
     ON CONFLICT(slug) DO UPDATE SET
       tenant_id = excluded.tenant_id,
       name = excluded.name,
       updated_at = excluded.updated_at`
  ).bind(projectId, tenant.id, projectSlug, projectName, publicStatusToken, now).run();
  const project = await env.DB.prepare(
    "SELECT id, slug, name, public_status_token FROM projects WHERE slug = ?1"
  ).bind(projectSlug).first();
  const agentToken = crypto.randomUUID();
  const agentTokenHash = await sha256Hex(agentToken);
  await env.DB.prepare(
    `INSERT INTO agent_tokens (id, project_id, name, token_hash, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5)`
  ).bind(crypto.randomUUID(), project.id, `${project.slug}-default-agent`, agentTokenHash, now).run();
  return {
    tenant,
    project,
    issued: {
      agentToken,
      publicStatusToken: project.public_status_token
    }
  };
}
async function upsertNode(env, body) {
  assertDb2(env);
  const project = await requireProject2(env, body.projectSlug);
  const slug = normalizeSlug(body.slug || body.name, "node");
  const now = nowIso();
  const nodeId = crypto.randomUUID();
  const expectedHeartbeatSec = coerceInteger(
    body.expectedHeartbeatSec,
    DEFAULT_HEARTBEAT_SEC,
    15,
    3600
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
       updated_at = excluded.updated_at`
  ).bind(
    nodeId,
    project.id,
    slug,
    body.name || slug,
    body.hostname || null,
    body.region || null,
    expectedHeartbeatSec,
    JSON.stringify(body.metadata || {}),
    now
  ).run();
  return env.DB.prepare(
    `SELECT id, project_id, slug, name, hostname, region, expected_heartbeat_sec, status, last_heartbeat_at
     FROM nodes WHERE project_id = ?1 AND slug = ?2`
  ).bind(project.id, slug).first();
}
async function upsertChannel(env, body) {
  assertDb2(env);
  const project = await requireProject2(env, body.projectSlug);
  const node = body.nodeSlug ? await ensureNodeForChannel(env, project, {
    slug: body.nodeSlug,
    name: body.nodeName || body.name || body.nodeSlug,
    hostname: body.nodeHostname || null,
    region: body.nodeRegion || null,
    expectedHeartbeatSec: body.expectedHeartbeatSec || DEFAULT_HEARTBEAT_SEC
  }) : null;
  const protocol = String(body.protocol || "").toLowerCase();
  if (!["http", "https", "head", "tcp", "tls"].includes(protocol)) {
    throw new HttpError(400, "invalid_protocol", "protocol must be one of http, https, head, tcp, tls");
  }
  const slug = normalizeSlug(body.slug || body.name || body.target, "channel");
  parseTarget(body.target, protocol === "head" ? "https" : protocol);
  const intervalSec = coerceInteger(body.intervalSec, 60, 15, 3600);
  const timeoutMs = coerceInteger(body.timeoutMs, DEFAULT_HTTP_TIMEOUT_MS, 1e3, 3e4);
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
       updated_at = excluded.updated_at`
  ).bind(
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
    now
  ).run();
  return env.DB.prepare(
    `SELECT id, project_id, node_id, slug, name, protocol, target, status, last_checked_at, last_error, consecutive_failures
     FROM channels WHERE project_id = ?1 AND slug = ?2`
  ).bind(project.id, slug).first();
}
async function ensureNodeForChannel(env, project, nodeInput) {
  const slug = normalizeSlug(nodeInput?.slug || nodeInput?.name, "node");
  const existing = await env.DB.prepare(
    `SELECT id, project_id, slug, name, hostname, region, expected_heartbeat_sec, status, last_heartbeat_at
     FROM nodes
     WHERE project_id = ?1 AND slug = ?2`
  ).bind(project.id, slug).first();
  if (existing) {
    return existing;
  }
  return upsertNode(env, {
    projectSlug: project.slug,
    slug,
    name: nodeInput?.name || slug,
    hostname: nodeInput?.hostname || null,
    region: nodeInput?.region || null,
    expectedHeartbeatSec: nodeInput?.expectedHeartbeatSec || DEFAULT_HEARTBEAT_SEC,
    metadata: { placeholder: true, source: "channel_upsert" }
  });
}
async function ingestHeartbeat(env, token, body, request) {
  assertDb2(env);
  const project = await requireProject2(env, body.projectSlug || token.project_slug);
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
    metadata: body?.node?.metadata || body?.metrics || {}
  });
  const receivedAt = body.receivedAt || now;
  await env.DB.prepare(
    `UPDATE nodes
     SET status = ?1, last_heartbeat_at = ?2, last_heartbeat_ip = ?3, metadata_json = ?4, updated_at = ?5
     WHERE id = ?6`
  ).bind(
    body.status === "degraded" ? "degraded" : "healthy",
    receivedAt,
    request.headers.get("cf-connecting-ip"),
    JSON.stringify(body?.node?.metadata || body?.metrics || {}),
    now,
    node.id
  ).run();
  await env.DB.prepare(
    `INSERT INTO heartbeats (id, project_id, node_id, received_at, status, payload_json)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
  ).bind(crypto.randomUUID(), project.id, node.id, receivedAt, body.status || "healthy", JSON.stringify(body)).run();
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
      method: check.method
    });
    const observedAt = check.observedAt || receivedAt;
    const status = check.status === "pass" ? "pass" : "fail";
    const nextConsecutiveFailures = status === "pass" ? 0 : Number(channel.consecutive_failures || 0) + 1;
    await env.DB.prepare(
      `UPDATE channels
       SET status = ?1,
           last_checked_at = ?2,
           last_latency_ms = ?3,
           last_error = ?4,
           consecutive_failures = ?5,
           updated_at = ?6
       WHERE id = ?7`
    ).bind(
      statusFromCheckResult(status),
      observedAt,
      check.latencyMs || null,
      check.error || null,
      nextConsecutiveFailures,
      now,
      channel.id
    ).run();
    await env.DB.prepare(
      `INSERT INTO channel_results (id, channel_id, observed_at, status, latency_ms, details_json)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
    ).bind(
      crypto.randomUUID(),
      channel.id,
      observedAt,
      status,
      check.latencyMs || null,
      JSON.stringify(check)
    ).run();
    await syncChannelIncident(env, project.id, channel.id, status, check.error || "Agent-reported failure");
    processedChecks.push({
      slug: channel.slug,
      status,
      latencyMs: check.latencyMs || null
    });
  }
  await syncNodeStaleIncident(env, project.id, node.id, false);
  return {
    project: project.slug,
    node: node.slug,
    receivedAt,
    checks: processedChecks
  };
}
async function getPublicStatus(env, projectSlug, token) {
  assertDb2(env);
  const project = await env.DB.prepare(
    "SELECT id, slug, name, public_status_token FROM projects WHERE slug = ?1"
  ).bind(projectSlug).first();
  if (!project) {
    throw new HttpError(404, "project_not_found", `Project "${projectSlug}" was not found`);
  }
  if (!token || token !== project.public_status_token) {
    throw new HttpError(401, "unauthorized", "Public status token is required");
  }
  return getProjectStatus(env, project.slug);
}
async function getProjectStatus(env, projectSlug) {
  assertDb2(env);
  const project = await requireProject2(env, projectSlug);
  const nodes = await env.DB.prepare(
    `SELECT slug, name, hostname, region, status, last_heartbeat_at, expected_heartbeat_sec
     FROM nodes
     WHERE project_id = ?1
     ORDER BY slug`
  ).bind(project.id).all();
  const channels = await env.DB.prepare(
    `SELECT slug, name, protocol, target, status, last_checked_at, last_latency_ms, last_error, consecutive_failures
     FROM channels
     WHERE project_id = ?1
     ORDER BY slug`
  ).bind(project.id).all();
  const incidents = await env.DB.prepare(
    `SELECT id, kind, severity, status, title, summary, first_seen_at, last_seen_at, resolved_at, ai_summary
     FROM incidents
     WHERE project_id = ?1
     ORDER BY
       CASE status WHEN 'open' THEN 0 ELSE 1 END,
       last_seen_at DESC`
  ).bind(project.id).all();
  const overall = deriveOverallStatus(nodes.results, channels.results, incidents.results);
  return {
    project: { slug: project.slug, name: project.name },
    overall,
    nodes: nodes.results,
    channels: channels.results,
    incidents: incidents.results
  };
}
async function listIncidents(env, projectSlug) {
  assertDb2(env);
  if (!projectSlug) {
    return env.DB.prepare(
      `SELECT id, project_id, node_id, channel_id, kind, severity, status, title, summary, ai_summary, first_seen_at, last_seen_at, resolved_at
       FROM incidents
       ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, last_seen_at DESC
       LIMIT 100`
    ).all().then((res) => res.results);
  }
  const project = await requireProject2(env, projectSlug);
  return env.DB.prepare(
    `SELECT id, project_id, node_id, channel_id, kind, severity, status, title, summary, ai_summary, first_seen_at, last_seen_at, resolved_at
     FROM incidents
     WHERE project_id = ?1
     ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, last_seen_at DESC
     LIMIT 100`
  ).bind(project.id).all().then((res) => res.results);
}
async function listIncidentEvents(env, incidentId) {
  assertDb2(env);
  const incident = await env.DB.prepare("SELECT id FROM incidents WHERE id = ?1").bind(incidentId).first();
  if (!incident) {
    throw new HttpError(404, "incident_not_found", `Incident "${incidentId}" was not found`);
  }
  const result = await env.DB.prepare(
    `SELECT id, incident_id, kind, payload_json, created_at
     FROM incident_events
     WHERE incident_id = ?1
     ORDER BY created_at ASC`
  ).bind(incidentId).all();
  return result.results.map((row) => ({
    ...row,
    payload: safeJsonParse2(row.payload_json, {})
  }));
}
async function listAgentTokens(env, projectSlug) {
  assertDb2(env);
  if (projectSlug) {
    const project = await requireProject2(env, projectSlug);
    return env.DB.prepare(
      `SELECT at.id, at.project_id, p.slug AS project_slug, at.name, at.created_at, at.last_used_at, at.revoked_at
       FROM agent_tokens at
       JOIN projects p ON p.id = at.project_id
       WHERE at.project_id = ?1
       ORDER BY at.created_at DESC`
    ).bind(project.id).all().then((res) => res.results);
  }
  return env.DB.prepare(
    `SELECT at.id, at.project_id, p.slug AS project_slug, at.name, at.created_at, at.last_used_at, at.revoked_at
     FROM agent_tokens at
     JOIN projects p ON p.id = at.project_id
     ORDER BY at.created_at DESC
     LIMIT 100`
  ).all().then((res) => res.results);
}
async function issueAgentToken(env, body) {
  assertDb2(env);
  const project = await requireProject2(env, body.projectSlug);
  const now = nowIso();
  const token = crypto.randomUUID();
  const tokenHash = await sha256Hex(token);
  const name = String(body.name || `${project.slug}-agent-${now.slice(11, 19).replace(/:/g, "")}`);
  const id = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO agent_tokens (id, project_id, name, token_hash, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5)`
  ).bind(id, project.id, name, tokenHash, now).run();
  const record = await env.DB.prepare(
    `SELECT at.id, at.project_id, p.slug AS project_slug, at.name, at.created_at, at.last_used_at, at.revoked_at
     FROM agent_tokens at
     JOIN projects p ON p.id = at.project_id
     WHERE at.id = ?1`
  ).bind(id).first();
  return {
    token,
    record
  };
}
async function revokeAgentToken(env, tokenId) {
  assertDb2(env);
  const token = await env.DB.prepare(
    `SELECT at.id, at.project_id, p.slug AS project_slug, at.name, at.created_at, at.last_used_at, at.revoked_at
     FROM agent_tokens at
     JOIN projects p ON p.id = at.project_id
     WHERE at.id = ?1`
  ).bind(tokenId).first();
  if (!token) {
    throw new HttpError(404, "agent_token_not_found", `Agent token "${tokenId}" was not found`);
  }
  if (!token.revoked_at) {
    await env.DB.prepare(
      "UPDATE agent_tokens SET revoked_at = ?1 WHERE id = ?2"
    ).bind(nowIso(), tokenId).run();
  }
  return env.DB.prepare(
    `SELECT at.id, at.project_id, p.slug AS project_slug, at.name, at.created_at, at.last_used_at, at.revoked_at
     FROM agent_tokens at
     JOIN projects p ON p.id = at.project_id
     WHERE at.id = ?1`
  ).bind(tokenId).first();
}
async function resolveIncident(env, incidentId, reason) {
  assertDb2(env);
  const now = nowIso();
  await env.DB.prepare(
    `UPDATE incidents
     SET status = 'resolved', resolved_at = ?1, last_seen_at = ?1, updated_at = ?1
     WHERE id = ?2`
  ).bind(now, incidentId).run();
  await appendIncidentEvent2(env, incidentId, "resolved", { reason });
  return env.DB.prepare("SELECT * FROM incidents WHERE id = ?1").bind(incidentId).first();
}
async function analyzeIncidentWithAi(env, incidentId) {
  assertDb2(env);
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
     WHERE i.id = ?1`
  ).bind(incidentId).first();
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
    JSON.stringify(incident, null, 2)
  ].join("\n");
  const response = await env.AI.run(model, {
    prompt,
    max_tokens: 300
  });
  const text = extractAiText(response);
  await env.DB.prepare("UPDATE incidents SET ai_summary = ?1, updated_at = ?2 WHERE id = ?3").bind(text, nowIso(), incidentId).run();
  await appendIncidentEvent2(env, incidentId, "ai_analysis", { model, text });
  return { incidentId, model, analysis: text };
}
async function runScheduledSweep(env, scheduledTime = Date.now(), options = {}) {
  assertDb2(env);
  const now = nowIso(scheduledTime);
  const scopedProject = options.projectSlug ? await requireProject2(env, options.projectSlug) : null;
  const nodesQuery = scopedProject ? env.DB.prepare(
    `SELECT id, project_id, slug, expected_heartbeat_sec, last_heartbeat_at
         FROM nodes
         WHERE project_id = ?1`
  ).bind(scopedProject.id) : env.DB.prepare(
    `SELECT id, project_id, slug, expected_heartbeat_sec, last_heartbeat_at
         FROM nodes`
  );
  const channelsQuery = scopedProject ? env.DB.prepare(
    `SELECT id, project_id, protocol, target, timeout_ms, expected_statuses_json
         FROM channels
         WHERE project_id = ?1`
  ).bind(scopedProject.id) : env.DB.prepare(
    `SELECT id, project_id, protocol, target, timeout_ms, expected_statuses_json
         FROM channels`
  );
  const nodes = await nodesQuery.all();
  const summary = {
    scope: scopedProject ? { project: scopedProject.slug } : { project: null },
    startedAt: now,
    nodesEvaluated: 0,
    nodesMarkedStale: 0,
    nodesHealthy: 0,
    channelsEvaluated: 0,
    channelsPassed: 0,
    channelsFailed: 0
  };
  for (const node of nodes.results) {
    const stale = isNodeStale(node.last_heartbeat_at, node.expected_heartbeat_sec || DEFAULT_HEARTBEAT_SEC, scheduledTime);
    await env.DB.prepare(
      "UPDATE nodes SET status = ?1, updated_at = ?2 WHERE id = ?3"
    ).bind(stale ? "stale" : "healthy", now, node.id).run();
    await syncNodeStaleIncident(env, node.project_id, node.id, stale);
    summary.nodesEvaluated += 1;
    if (stale) {
      summary.nodesMarkedStale += 1;
    } else {
      summary.nodesHealthy += 1;
    }
  }
  const channels = await channelsQuery.all();
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
       WHERE id = ?6`
    ).bind(
      statusFromCheckResult(checkResult.status),
      checkResult.observedAt,
      checkResult.latencyMs,
      checkResult.error,
      checkResult.status,
      channel.id
    ).run();
    await env.DB.prepare(
      `INSERT INTO channel_results (id, channel_id, observed_at, status, latency_ms, details_json)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
    ).bind(
      crypto.randomUUID(),
      channel.id,
      checkResult.observedAt,
      checkResult.status,
      checkResult.latencyMs,
      JSON.stringify(checkResult)
    ).run();
    await syncChannelIncident(
      env,
      channel.project_id,
      channel.id,
      checkResult.status,
      checkResult.error || "Scheduled check failed"
    );
    summary.channelsEvaluated += 1;
    if (checkResult.status === "pass") {
      summary.channelsPassed += 1;
    } else {
      summary.channelsFailed += 1;
    }
  }
  return summary;
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
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    const allowedStatuses = expectedHttpStatuses(JSON.parse(channel.expected_statuses_json || "[]"));
    const passed = allowedStatuses.includes(response.status);
    return {
      status: passed ? "pass" : "fail",
      observedAt,
      latencyMs: Date.now() - startedAt,
      error: passed ? null : `Unexpected HTTP status ${response.status}`
    };
  } catch (error) {
    return {
      status: "fail",
      observedAt,
      latencyMs: Date.now() - startedAt,
      error: error?.message || "Unknown check failure"
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
    summary: `${node.name || node.slug} exceeded the heartbeat threshold and is considered stale.`
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
    summary: errorMessage || `Scheduled or agent check failed for ${channel.target}`
  });
}
async function openOrRefreshIncident(env, incident) {
  const now = nowIso();
  const existing = await findOpenIncidentByKey(env, incident.dedupeKey);
  if (existing) {
    await env.DB.prepare(
      `UPDATE incidents
       SET severity = ?1, summary = ?2, last_seen_at = ?3, updated_at = ?3
       WHERE id = ?4`
    ).bind(incident.severity, incident.summary, now, existing.id).run();
    await appendIncidentEvent2(env, existing.id, "observed", { summary: incident.summary });
    return existing.id;
  }
  const incidentId = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO incidents (
       id, project_id, node_id, channel_id, dedupe_key, kind, severity, status, title, summary,
       first_seen_at, last_seen_at, created_at, updated_at
     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'open', ?8, ?9, ?10, ?10, ?10, ?10)`
  ).bind(
    incidentId,
    incident.projectId,
    incident.nodeId,
    incident.channelId,
    incident.dedupeKey,
    incident.kind,
    incident.severity,
    incident.title,
    incident.summary,
    now
  ).run();
  await appendIncidentEvent2(env, incidentId, "opened", { summary: incident.summary });
  await scheduleIncidentRemediation(env, incidentId);
  return incidentId;
}
async function appendIncidentEvent2(env, incidentId, kind, payload) {
  await env.DB.prepare(
    `INSERT INTO incident_events (id, incident_id, kind, payload_json, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5)`
  ).bind(crypto.randomUUID(), incidentId, kind, JSON.stringify(payload || {}), nowIso()).run();
}
async function findOpenIncidentByKey(env, dedupeKey) {
  return env.DB.prepare(
    "SELECT id, status FROM incidents WHERE dedupe_key = ?1 AND status = 'open' LIMIT 1"
  ).bind(dedupeKey).first();
}
function deriveOverallStatus(nodes, channels, incidents) {
  if (incidents.some((incident) => incident.status === "open" && incident.severity === "critical")) {
    return "critical";
  }
  if (nodes.some((node) => ["degraded", "stale"].includes(node.status)) || channels.some((channel) => channel.status === "degraded")) {
    return "degraded";
  }
  if (nodes.length === 0 && channels.length === 0) {
    return "empty";
  }
  return "healthy";
}
async function requireProject2(env, projectSlug) {
  const project = await env.DB.prepare("SELECT id, slug, name, public_status_token FROM projects WHERE slug = ?1").bind(projectSlug).first();
  if (!project) {
    throw new HttpError(404, "project_not_found", `Project "${projectSlug}" was not found`);
  }
  return project;
}
function assertDb2(env) {
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
function safeJsonParse2(value, fallback = null) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}
export {
  index_default as default
};
