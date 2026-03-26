import {
  DEFAULT_HTTP_TIMEOUT_MS,
  HttpError,
  coerceInteger,
  expectedHttpStatuses,
  normalizeSlug,
  nowIso,
  parseTarget,
  statusFromCheckResult,
} from "./core.js";

const ACTION_STATUS_SET = new Set(["queued", "leased", "running", "succeeded", "failed", "canceled", "expired", "pending"]);
const APPROVAL_STATUS_SET = new Set(["not_required", "pending", "approved", "rejected"]);
const RUNBOOK_SCOPE_SET = new Set(["node", "channel", "project"]);
const ACTION_TYPE_SET = new Set(["restart_service", "reload_service", "switch_upstream", "drain_node", "collect_diagnostics"]);
const POLICY_MODE_SET = new Set(["suggest", "manual", "auto"]);

export async function listRunbooks(env) {
  assertDb(env);
  const result = await env.DB.prepare(
    `SELECT id, slug, title, scope, action_type, params_schema_json, requires_approval_default, enabled, created_at, updated_at
     FROM runbooks
     ORDER BY slug`,
  ).all();
  return result.results.map(deserializeRunbook);
}

export async function upsertRunbook(env, body) {
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
      "runbook action_type must be one of restart_service, reload_service, switch_upstream, drain_node, collect_diagnostics",
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
       updated_at = excluded.updated_at`,
  )
    .bind(
      id,
      slug,
      title,
      scope,
      actionType,
      JSON.stringify(body.paramsSchema || body.params_schema || {}),
      truthyInteger(body.requiresApprovalDefault, 1),
      truthyInteger(body.enabled, 1),
      now,
    )
    .run();

  return getRunbookBySlug(env, slug);
}

export async function listPolicies(env, projectSlug) {
  assertDb(env);
  const project = projectSlug ? await requireProject(env, projectSlug) : null;
  const statement = project
    ? env.DB.prepare(
        `SELECT rp.*, p.slug AS project_slug, rb.slug AS runbook_slug, rb.title AS runbook_title, rb.action_type, rb.scope
         FROM remediation_policies rp
         JOIN projects p ON p.id = rp.project_id
         JOIN runbooks rb ON rb.id = rp.runbook_id
         WHERE rp.project_id = ?1
         ORDER BY rp.created_at DESC`,
      ).bind(project.id)
    : env.DB.prepare(
        `SELECT rp.*, p.slug AS project_slug, rb.slug AS runbook_slug, rb.title AS runbook_title, rb.action_type, rb.scope
         FROM remediation_policies rp
         JOIN projects p ON p.id = rp.project_id
         JOIN runbooks rb ON rb.id = rp.runbook_id
         ORDER BY rp.created_at DESC
         LIMIT 200`,
      );

  const result = await statement.all();
  return result.results.map(deserializePolicy);
}

export async function upsertPolicy(env, body) {
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
       updated_at = excluded.updated_at`,
  )
    .bind(
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
      now,
    )
    .run();

  return getPolicyById(env, id);
}

export async function listNodeCapabilities(env, projectSlug, nodeSlug = null) {
  assertDb(env);
  const project = await requireProject(env, projectSlug);
  const statement = nodeSlug
    ? env.DB.prepare(
        `SELECT nc.*, n.slug AS node_slug, p.slug AS project_slug
         FROM node_capabilities nc
         JOIN nodes n ON n.id = nc.node_id
         JOIN projects p ON p.id = n.project_id
         WHERE n.project_id = ?1 AND n.slug = ?2
         ORDER BY nc.action_type`,
      ).bind(project.id, normalizeSlug(nodeSlug, "node"))
    : env.DB.prepare(
        `SELECT nc.*, n.slug AS node_slug, p.slug AS project_slug
         FROM node_capabilities nc
         JOIN nodes n ON n.id = nc.node_id
         JOIN projects p ON p.id = n.project_id
         WHERE n.project_id = ?1
         ORDER BY n.slug, nc.action_type`,
      ).bind(project.id);

  const result = await statement.all();
  return result.results.map(deserializeNodeCapability);
}

export async function upsertNodeCapability(env, body) {
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
       updated_at = excluded.updated_at`,
  )
    .bind(id, node.id, actionType, truthyInteger(body.enabled, 1), JSON.stringify(body.config || {}), now)
    .run();

  const result = await env.DB.prepare(
    `SELECT nc.*, n.slug AS node_slug, p.slug AS project_slug
     FROM node_capabilities nc
     JOIN nodes n ON n.id = nc.node_id
     JOIN projects p ON p.id = n.project_id
     WHERE nc.node_id = ?1 AND nc.action_type = ?2`,
  )
    .bind(node.id, actionType)
    .first();
  return deserializeNodeCapability(result);
}

export async function listActions(env, filters = {}) {
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
     LIMIT 200`,
  )
    .bind(...bindings)
    .all();
  return result.results.map(deserializeAction);
}

export async function listActionEvents(env, actionId) {
  assertDb(env);
  await requireAction(env, actionId);
  const result = await env.DB.prepare(
    `SELECT id, action_id, kind, payload_json, created_at
     FROM remediation_action_events
     WHERE action_id = ?1
     ORDER BY created_at ASC`,
  )
    .bind(actionId)
    .all();
  return result.results.map((row) => ({
    ...row,
    payload: safeJsonParse(row.payload_json, {}),
  }));
}

export async function planIncidentRemediation(env, incidentId) {
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
      autoCreatable: item.autoCreatable,
    })),
    activeActions: actions.filter((action) => ["pending", "queued", "leased", "running"].includes(action.status)),
    recommendation: buildRemediationRecommendation(incident, matches),
  };
}

export async function createIncidentRemediationAction(env, incidentId, body) {
  assertDb(env);
  const incident = await requireIncident(env, incidentId);
  const creation = await prepareActionCreation(env, incident, body);
  return createRemediationActionRecord(env, creation);
}

export async function approveRemediationAction(env, actionId, body = {}) {
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
       WHERE id = ?2`,
    )
      .bind(now, actionId)
      .run();
    await appendActionEvent(env, actionId, "approved", {
      by: body.by || "admin",
      note: body.note || null,
    });
  } else {
    await env.DB.prepare(
      `UPDATE remediation_actions
       SET approval_status = 'rejected', status = 'canceled', finished_at = ?1, updated_at = ?1
       WHERE id = ?2`,
    )
      .bind(now, actionId)
      .run();
    await appendActionEvent(env, actionId, "rejected", {
      by: body.by || "admin",
      note: body.note || null,
    });
  }

  return requireAction(env, actionId);
}

export async function cancelRemediationAction(env, actionId, body = {}) {
  assertDb(env);
  await requireAction(env, actionId);
  const now = nowIso();
  await env.DB.prepare(
    `UPDATE remediation_actions
     SET status = 'canceled', finished_at = ?1, updated_at = ?1
     WHERE id = ?2 AND status NOT IN ('succeeded', 'failed', 'canceled', 'expired')`,
  )
    .bind(now, actionId)
    .run();
  await appendActionEvent(env, actionId, "canceled", {
    by: body.by || "admin",
    reason: body.reason || "canceled_by_admin",
  });
  return requireAction(env, actionId);
}

export async function pullAgentActions(env, token, body) {
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
     LIMIT ?3`,
  )
    .bind(project.id, node.id, limit)
    .all();

  const leased = [];
  for (const row of result.results) {
    const leaseToken = crypto.randomUUID();
    const now = nowIso();
    const leaseExpiresAt = nowIso(Date.now() + coerceInteger(body.leaseSec, 120, 30, 900) * 1000);
    const update = await env.DB.prepare(
      `UPDATE remediation_actions
       SET status = 'leased', lease_token = ?1, lease_expires_at = ?2, updated_at = ?3
       WHERE id = ?4 AND status = 'queued'`,
    )
      .bind(leaseToken, leaseExpiresAt, now, row.id)
      .run();

    if (!update.meta?.changes) {
      continue;
    }

    await appendActionEvent(env, row.id, "leased", {
      nodeSlug: node.slug,
      leaseExpiresAt,
    });

    const action = await requireAction(env, row.id);
    leased.push({
      ...action,
      leaseToken,
    });
  }

  return {
    node: node.slug,
    actions: leased,
  };
}

export async function submitActionResult(env, token, actionId, body) {
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
       WHERE id = ?2`,
    )
      .bind(now, actionId)
      .run();
    await appendActionEvent(env, actionId, "started", {
      summary: body.summary || null,
      result: body.result || {},
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
     WHERE id = ?6`,
  )
    .bind(
      resultStatus,
      now,
      body.summary || null,
      JSON.stringify(body.result || {}),
      verify.verifyStatus,
      actionId,
    )
    .run();

  await appendActionEvent(env, actionId, "result", {
    status: resultStatus,
    summary: body.summary || null,
    result: body.result || {},
  });
  await appendActionEvent(env, actionId, "verified", verify.eventPayload);

  if (verify.resolveIncidentId) {
    await env.DB.prepare(
      `UPDATE incidents
       SET status = 'resolved', resolved_at = ?1, last_seen_at = ?1, updated_at = ?1
       WHERE id = ?2 AND status = 'open'`,
    )
      .bind(now, verify.resolveIncidentId)
      .run();
  }

  return requireAction(env, actionId);
}

export async function scheduleIncidentRemediation(env, incidentId) {
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
        actionType: runbook.actionType,
      });
      continue;
    }
    if (policy.mode === "auto" && !item.autoCreatable) {
      await appendIncidentEvent(env, incident.id, "remediation_skipped", {
        policyId: policy.id,
        reason: "auto_policy_not_creatable",
        runbook: runbook.slug,
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
        cooldownSec: policy.cooldownSec,
      });
      continue;
    }

    const attemptNo = (await countActionsForIncidentRunbook(env, incident.id, runbook.id)) + 1;
    if (attemptNo > policy.maxAttempts) {
      continue;
    }

    const approvalStatus =
      policy.mode === "manual"
        ? "pending"
        : runbook.requiresApprovalDefault
          ? "pending"
          : "not_required";
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
      nodeId: incident.node_id || incident.channel_node_id || null,
      channelId: incident.channel_id || null,
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
  const attemptNo = (await countActionsForIncidentRunbook(env, incident.id, runbook.id)) + 1;
  const approvalStatus = normalizeApprovalStatus(
    body.approvalStatus,
    body.approved === true ? "approved" : runbook.requiresApprovalDefault ? "pending" : "not_required",
  );
  const status = approvalStatus === "approved" || approvalStatus === "not_required" ? "queued" : "pending";
  const params = {
    ...(policy ? safeJsonParse(policy.params_json, {}) : {}),
    ...(body.params || {}),
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
    nodeId: incident.node_id || incident.channel_node_id || null,
    channelId: incident.channel_id || null,
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
     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'pending', ?12, ?12)`,
  )
    .bind(
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
      now,
    )
    .run();

  await appendActionEvent(env, id, "queued", {
    source: creation.source,
    approvalStatus: creation.approvalStatus,
    status: creation.status,
    policyId: creation.policy?.id || null,
    params: creation.params || {},
  });
  await appendIncidentEvent(env, creation.incident.id, "remediation_action_created", {
    actionId: id,
    runbookId,
    source: creation.source,
  });

  return requireAction(env, id);
}

async function verifyRemediationAction(env, action, resultStatus, body) {
  if (resultStatus !== "succeeded") {
    return {
      verifyStatus: "failed",
      eventPayload: {
        verifyStatus: "failed",
        reason: body.summary || "action_failed",
      },
      resolveIncidentId: null,
    };
  }

  if (!action.channel_id) {
    return {
      verifyStatus: "pending",
      eventPayload: {
        verifyStatus: "pending",
        reason: "awaiting_next_heartbeat",
      },
      resolveIncidentId: null,
    };
  }

  const channel = await env.DB.prepare(
    `SELECT id, project_id, protocol, target, timeout_ms, expected_statuses_json
     FROM channels
     WHERE id = ?1`,
  )
    .bind(action.channel_id)
    .first();

  if (!channel || !["http", "https", "head"].includes(channel.protocol)) {
    return {
      verifyStatus: "skipped",
      eventPayload: {
        verifyStatus: "skipped",
        reason: "channel_verification_not_supported",
      },
      resolveIncidentId: null,
    };
  }

  const check = await executeChannelVerification(channel);
  return {
    verifyStatus: check.status === "pass" ? "passed" : "failed",
    eventPayload: {
      verifyStatus: check.status === "pass" ? "passed" : "failed",
      observedAt: check.observedAt,
      latencyMs: check.latencyMs,
      error: check.error,
    },
    resolveIncidentId: check.status === "pass" ? action.incident_id : null,
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
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    const allowed = expectedHttpStatuses(safeJsonParse(channel.expected_statuses_json, []));
    const passed = allowed.includes(response.status);
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
      error: error?.message || "Verification failed",
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
       AND rb.enabled = 1`,
  )
    .bind(incident.project_id, incident.kind)
    .all();

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

    const capabilityNodeId = incident.node_id || incident.channel_node_id || null;
    const capability = capabilityNodeId
      ? await findNodeCapability(env, capabilityNodeId, row.action_type)
      : null;
    const effectiveParams = {
      ...safeJsonParse(policy.params_json, {}),
    };
    matches.push({
      policy,
      runbook: row,
      capability,
      effectiveParams,
      autoCreatable:
        policy.mode === "auto" &&
        (!row.requires_approval_default || row.requires_approval_default === 0) &&
        (!!capability || row.scope === "project"),
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
      aiSummary: incident.ai_summary || null,
    };
  }

  const candidate = matches[0];
  return {
    action: candidate.runbook.action_type,
    runbook: candidate.runbook.runbook_slug,
    reason: `${candidate.policy.mode} policy matched incident ${incident.kind}`,
    source: incident.ai_summary ? "policy_engine+incident_ai_summary" : "policy_engine",
    aiSummary: incident.ai_summary || null,
  };
}

async function resolveRunbook(env, body) {
  if (body.runbookId) {
    const row = await env.DB.prepare(
      `SELECT id, slug, title, scope, action_type, params_schema_json, requires_approval_default, enabled, created_at, updated_at
       FROM runbooks WHERE id = ?1`,
    )
      .bind(body.runbookId)
      .first();
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
     FROM runbooks WHERE slug = ?1`,
  )
    .bind(slug)
    .first();
  return row ? deserializeRunbook(row) : null;
}

async function getPolicyById(env, id) {
  const row = await env.DB.prepare(
    `SELECT rp.*, p.slug AS project_slug, rb.slug AS runbook_slug, rb.title AS runbook_title, rb.action_type, rb.scope
     FROM remediation_policies rp
     JOIN projects p ON p.id = rp.project_id
     JOIN runbooks rb ON rb.id = rp.runbook_id
     WHERE rp.id = ?1`,
  )
    .bind(id)
    .first();
  if (!row) {
    throw new HttpError(404, "policy_not_found", `Policy "${id}" was not found`);
  }
  return deserializePolicy(row);
}

async function requirePolicy(env, id) {
  const row = await env.DB.prepare(
    `SELECT * FROM remediation_policies WHERE id = ?1`,
  )
    .bind(id)
    .first();
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
     WHERE ra.id = ?1`,
  )
    .bind(id)
    .first();
  if (!row) {
    throw new HttpError(404, "action_not_found", `Action "${id}" was not found`);
  }
  return deserializeAction(row);
}

async function requireIncident(env, id) {
  const row = await env.DB.prepare(
    `SELECT i.*, p.slug AS project_slug, n.slug AS node_slug, n.region AS node_region,
            c.slug AS channel_slug, c.protocol AS channel_protocol, c.target AS channel_target, c.node_id AS channel_node_id
     FROM incidents i
     JOIN projects p ON p.id = i.project_id
     LEFT JOIN nodes n ON n.id = i.node_id
     LEFT JOIN channels c ON c.id = i.channel_id
     WHERE i.id = ?1`,
  )
    .bind(id)
    .first();
  if (!row) {
    throw new HttpError(404, "incident_not_found", `Incident "${id}" was not found`);
  }
  return row;
}

async function requireProject(env, projectSlug) {
  const project = await env.DB.prepare(
    "SELECT id, slug, name, public_status_token FROM projects WHERE slug = ?1",
  )
    .bind(projectSlug)
    .first();
  if (!project) {
    throw new HttpError(404, "project_not_found", `Project "${projectSlug}" was not found`);
  }
  return project;
}

async function requireNode(env, projectId, nodeSlug) {
  const slug = normalizeSlug(nodeSlug, "node");
  const node = await env.DB.prepare(
    `SELECT * FROM nodes WHERE project_id = ?1 AND slug = ?2`,
  )
    .bind(projectId, slug)
    .first();
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
     WHERE nc.node_id = ?1 AND nc.action_type = ?2 AND nc.enabled = 1`,
  )
    .bind(nodeId, actionType)
    .first();
  return row || null;
}

async function findActiveActionForIncidentRunbook(env, incidentId, runbookId) {
  return env.DB.prepare(
    `SELECT id
     FROM remediation_actions
     WHERE incident_id = ?1
       AND runbook_id = ?2
       AND status IN ('pending', 'queued', 'leased', 'running')
     LIMIT 1`,
  )
    .bind(incidentId, runbookId)
    .first();
}

async function countActionsForIncidentRunbook(env, incidentId, runbookId) {
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS count
     FROM remediation_actions
     WHERE incident_id = ?1 AND runbook_id = ?2`,
  )
    .bind(incidentId, runbookId)
    .first();
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
     LIMIT 1`,
  )
    .bind(incident.project_id, runbookId, incident.node_id || null, incident.channel_id || null)
    .first();

  if (!row) {
    return false;
  }

  const ts = Date.parse(row.finished_at || row.created_at || "");
  if (!Number.isFinite(ts)) {
    return false;
  }
  return Date.now() - ts < cooldownSec * 1000;
}

async function appendActionEvent(env, actionId, kind, payload) {
  await env.DB.prepare(
    `INSERT INTO remediation_action_events (id, action_id, kind, payload_json, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5)`,
  )
    .bind(crypto.randomUUID(), actionId, kind, JSON.stringify(payload || {}), nowIso())
    .run();
}

async function appendIncidentEvent(env, incidentId, kind, payload) {
  await env.DB.prepare(
    `INSERT INTO incident_events (id, incident_id, kind, payload_json, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5)`,
  )
    .bind(crypto.randomUUID(), incidentId, kind, JSON.stringify(payload || {}), nowIso())
    .run();
}

async function expireLeases(env) {
  await env.DB.prepare(
    `UPDATE remediation_actions
     SET status = 'expired', lease_token = NULL, lease_expires_at = NULL, updated_at = ?1
     WHERE status IN ('leased', 'running')
       AND lease_expires_at IS NOT NULL
       AND lease_expires_at < ?1`,
  )
    .bind(nowIso())
    .run();
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
    updatedAt: row.updated_at,
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
    updatedAt: row.updated_at,
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
    updatedAt: row.updated_at,
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
    lease_token: row.lease_token,
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
    resolvedAt: row.resolved_at,
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
  if (value === undefined || value === null || value === "") return fallback;
  return value ? 1 : 0;
}

function safeJsonParse(value, fallback = null) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}
