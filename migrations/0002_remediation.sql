CREATE TABLE IF NOT EXISTS runbooks (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  scope TEXT NOT NULL,
  action_type TEXT NOT NULL,
  params_schema_json TEXT NOT NULL DEFAULT '{}',
  requires_approval_default INTEGER NOT NULL DEFAULT 1,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS remediation_policies (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  incident_kind TEXT NOT NULL,
  severity TEXT,
  runbook_id TEXT NOT NULL,
  mode TEXT NOT NULL,
  max_attempts INTEGER NOT NULL DEFAULT 1,
  cooldown_sec INTEGER NOT NULL DEFAULT 900,
  match_json TEXT NOT NULL DEFAULT '{}',
  params_json TEXT NOT NULL DEFAULT '{}',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (project_id) REFERENCES projects(id),
  FOREIGN KEY (runbook_id) REFERENCES runbooks(id)
);

CREATE TABLE IF NOT EXISTS node_capabilities (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  action_type TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  config_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (node_id) REFERENCES nodes(id),
  UNIQUE(node_id, action_type)
);

CREATE TABLE IF NOT EXISTS remediation_actions (
  id TEXT PRIMARY KEY,
  incident_id TEXT,
  project_id TEXT NOT NULL,
  node_id TEXT,
  channel_id TEXT,
  runbook_id TEXT NOT NULL,
  source TEXT NOT NULL,
  approval_status TEXT NOT NULL,
  status TEXT NOT NULL,
  lease_token TEXT,
  lease_expires_at TEXT,
  params_json TEXT NOT NULL DEFAULT '{}',
  attempt_no INTEGER NOT NULL DEFAULT 1,
  started_at TEXT,
  finished_at TEXT,
  result_summary TEXT,
  result_json TEXT,
  verify_status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (incident_id) REFERENCES incidents(id),
  FOREIGN KEY (project_id) REFERENCES projects(id),
  FOREIGN KEY (node_id) REFERENCES nodes(id),
  FOREIGN KEY (channel_id) REFERENCES channels(id),
  FOREIGN KEY (runbook_id) REFERENCES runbooks(id)
);

CREATE TABLE IF NOT EXISTS remediation_action_events (
  id TEXT PRIMARY KEY,
  action_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (action_id) REFERENCES remediation_actions(id)
);

CREATE INDEX IF NOT EXISTS idx_policies_project_kind ON remediation_policies(project_id, incident_kind, enabled);
CREATE INDEX IF NOT EXISTS idx_capabilities_node_action ON node_capabilities(node_id, action_type, enabled);
CREATE INDEX IF NOT EXISTS idx_actions_project_status ON remediation_actions(project_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_actions_incident_runbook ON remediation_actions(incident_id, runbook_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_actions_lease ON remediation_actions(status, lease_expires_at);
CREATE INDEX IF NOT EXISTS idx_action_events_action_created ON remediation_action_events(action_id, created_at ASC);
