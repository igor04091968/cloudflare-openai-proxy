# Cloudflare Proxy Reliability Control Plane

This repository now hosts a Cloudflare Worker that acts as a control plane for a managed proxy support service.

The first MVP focuses on:

- tenant and project bootstrap;
- agent-issued heartbeats from proxy nodes;
- channel health tracking for HTTP, HTTPS, TCP, and TLS checks;
- incident creation and recovery tracking in D1;
- scheduled sweeps that detect stale nodes and run edge-side health checks;
- optional Workers AI incident summaries.

## Worker Resources

The Worker expects these bindings:

- `DB` - D1 database
- `ADMIN_TOKEN` - bearer token for admin API
- `AI` - optional Workers AI binding
- `AI_MODEL` - optional Workers AI model override

## Local Scripts

```bash
npm install
npm test
```

## Suggested Wrangler Setup

1. Create a D1 database:

```bash
npx wrangler d1 create proxy_reliability
```

2. Update `wrangler.toml` with the returned database IDs.

3. Apply the migration:

```bash
npx wrangler d1 migrations apply proxy_reliability
```

4. Set the admin secret:

```bash
npx wrangler secret put ADMIN_TOKEN
```

5. Deploy:

```bash
npx wrangler deploy
```

## API Overview

### Bootstrap a tenant and project

```bash
curl -X POST "$WORKER_URL/v1/admin/bootstrap" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant": { "slug": "demo", "name": "Demo Tenant" },
    "project": { "slug": "proxy-prod", "name": "Proxy Prod" }
  }'
```

The response includes:

- a generated `agentToken` for heartbeats;
- a generated `publicStatusToken` for public status views.

### Register or update a node

```bash
curl -X POST "$WORKER_URL/v1/admin/nodes" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "projectSlug": "proxy-prod",
    "slug": "gw-1",
    "name": "Gateway 1",
    "hostname": "gw1.example.net",
    "region": "eu-central",
    "expectedHeartbeatSec": 60
  }'
```

### Register or update a channel

```bash
curl -X POST "$WORKER_URL/v1/admin/channels" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "projectSlug": "proxy-prod",
    "nodeSlug": "gw-1",
    "slug": "gw1-https",
    "name": "GW1 HTTPS",
    "protocol": "https",
    "target": "https://gw1.example.net/health",
    "expectedStatuses": [200, 204],
    "intervalSec": 60,
    "timeoutMs": 5000
  }'
```

### Send a node heartbeat

```bash
curl -X POST "$WORKER_URL/v1/agent/heartbeat" \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "projectSlug": "proxy-prod",
    "status": "healthy",
    "node": {
      "slug": "gw-1",
      "name": "Gateway 1",
      "hostname": "gw1.example.net",
      "region": "eu-central"
    },
    "checks": [
      {
        "slug": "gw1-https",
        "name": "GW1 HTTPS",
        "protocol": "https",
        "target": "https://gw1.example.net/health",
        "status": "pass",
        "latencyMs": 82
      },
      {
        "slug": "gw1-socks",
        "name": "GW1 SOCKS",
        "protocol": "tcp",
        "target": "gw1.example.net:1080",
        "status": "fail",
        "error": "connection refused"
      }
    ]
  }'
```

### Query project status

Admin:

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$WORKER_URL/v1/admin/projects/proxy-prod/status"
```

Public:

```bash
curl "$WORKER_URL/v1/status/proxy-prod?token=$PUBLIC_STATUS_TOKEN"
```
