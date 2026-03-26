export function renderOperatorApp() {
  return new Response(buildOperatorHtml(), {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function buildOperatorHtml() {
  return `<!doctype html>
<html lang="ru">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Proxy Reliability Operator</title>
    <style>
      :root {
        --bg: #f4efe7;
        --bg-strong: #e7dfd1;
        --card: rgba(255, 255, 255, 0.86);
        --ink: #13202f;
        --muted: #536273;
        --line: rgba(19, 32, 47, 0.12);
        --accent: #0f766e;
        --accent-strong: #0a5e58;
        --warn: #b45309;
        --danger: #b42318;
        --ok: #166534;
        --shadow: 0 18px 48px rgba(19, 32, 47, 0.12);
      }

      * {
        box-sizing: border-box;
      }

      body {
        margin: 0;
        font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
        color: var(--ink);
        background:
          radial-gradient(circle at top left, rgba(15, 118, 110, 0.12), transparent 28%),
          radial-gradient(circle at top right, rgba(180, 83, 9, 0.12), transparent 24%),
          linear-gradient(180deg, #fbf8f1 0%, var(--bg) 100%);
      }

      .shell {
        display: grid;
        grid-template-columns: 320px minmax(0, 1fr);
        min-height: 100vh;
      }

      .sidebar {
        border-right: 1px solid var(--line);
        background: linear-gradient(180deg, rgba(255,255,255,0.65), rgba(255,255,255,0.2));
        backdrop-filter: blur(12px);
        padding: 20px;
      }

      .brand {
        margin-bottom: 18px;
      }

      .brand h1 {
        margin: 0;
        font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
        font-size: 20px;
        letter-spacing: 0.04em;
      }

      .brand p {
        margin: 6px 0 0;
        color: var(--muted);
        font-size: 13px;
        line-height: 1.5;
      }

      .token-box,
      .project-list,
      .panel,
      .section {
        background: var(--card);
        border: 1px solid var(--line);
        border-radius: 18px;
        box-shadow: var(--shadow);
      }

      .token-box,
      .project-list {
        padding: 16px;
      }

      label {
        display: block;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--muted);
        margin-bottom: 8px;
      }

      input,
      select,
      textarea {
        width: 100%;
        border: 1px solid var(--line);
        border-radius: 12px;
        padding: 12px 14px;
        font: inherit;
        color: var(--ink);
        background: rgba(255,255,255,0.9);
      }

      textarea {
        min-height: 120px;
        resize: vertical;
        font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
        font-size: 12px;
      }

      button {
        border: 0;
        border-radius: 999px;
        padding: 10px 14px;
        font: inherit;
        font-weight: 600;
        cursor: pointer;
        background: var(--accent);
        color: #fff;
      }

      button:hover {
        background: var(--accent-strong);
      }

      button.secondary {
        background: #fff;
        color: var(--ink);
        border: 1px solid var(--line);
      }

      button.warn {
        background: var(--warn);
      }

      button.danger {
        background: var(--danger);
      }

      button.ghost {
        background: transparent;
        color: var(--muted);
        border: 1px dashed var(--line);
      }

      .stack {
        display: grid;
        gap: 14px;
      }

      .row {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
        align-items: center;
      }

      .row > * {
        flex: 1 1 auto;
      }

      .project-item {
        border: 1px solid var(--line);
        border-radius: 14px;
        padding: 12px;
        background: rgba(255,255,255,0.65);
        cursor: pointer;
      }

      .project-item.active {
        border-color: rgba(15, 118, 110, 0.5);
        background: rgba(15, 118, 110, 0.1);
      }

      .project-item h3 {
        margin: 0 0 8px;
        font-size: 15px;
      }

      .project-item p {
        margin: 2px 0;
        font-size: 12px;
        color: var(--muted);
      }

      .main {
        padding: 20px;
        display: grid;
        gap: 16px;
      }

      .panel {
        padding: 18px;
      }

      .hero {
        display: flex;
        justify-content: space-between;
        gap: 16px;
        align-items: flex-start;
      }

      .hero h2 {
        margin: 0 0 6px;
        font-size: 28px;
      }

      .hero p {
        margin: 0;
        color: var(--muted);
      }

      .badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        border-radius: 999px;
        padding: 8px 12px;
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
      }

      .badge.healthy {
        color: var(--ok);
        background: rgba(22, 101, 52, 0.1);
      }

      .badge.degraded,
      .badge.warning {
        color: var(--warn);
        background: rgba(180, 83, 9, 0.12);
      }

      .badge.critical,
      .badge.failed,
      .badge.canceled,
      .badge.rejected {
        color: var(--danger);
        background: rgba(180, 35, 24, 0.12);
      }

      .badge.pending,
      .badge.queued,
      .badge.leased,
      .badge.running {
        color: var(--accent-strong);
        background: rgba(15, 118, 110, 0.12);
      }

      .metric-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 12px;
      }

      .metric {
        padding: 14px;
        border-radius: 16px;
        border: 1px solid var(--line);
        background: rgba(255,255,255,0.7);
      }

      .metric strong {
        display: block;
        font-size: 26px;
        margin-top: 6px;
      }

      .metric span {
        color: var(--muted);
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
      }

      .section {
        padding: 16px;
      }

      .section h3 {
        margin: 0 0 12px;
      }

      .grid-2 {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 16px;
      }

      .item-card {
        border: 1px solid var(--line);
        border-radius: 16px;
        padding: 14px;
        background: rgba(255,255,255,0.75);
      }

      .item-card h4 {
        margin: 0 0 8px;
        font-size: 15px;
      }

      .meta {
        color: var(--muted);
        font-size: 12px;
        line-height: 1.6;
      }

      .actions {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        margin-top: 12px;
      }

      .mono {
        font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
        font-size: 12px;
      }

      .empty {
        color: var(--muted);
        border: 1px dashed var(--line);
        border-radius: 14px;
        padding: 16px;
        text-align: center;
      }

      .toolbar {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
      }

      .status-line {
        font-size: 13px;
        color: var(--muted);
      }

      .toast {
        position: fixed;
        right: 18px;
        bottom: 18px;
        min-width: 280px;
        max-width: 440px;
        background: rgba(19, 32, 47, 0.92);
        color: #fff;
        padding: 14px 16px;
        border-radius: 16px;
        box-shadow: var(--shadow);
        opacity: 0;
        transform: translateY(16px);
        pointer-events: none;
        transition: all 0.18s ease;
      }

      .toast.visible {
        opacity: 1;
        transform: translateY(0);
      }

      @media (max-width: 1100px) {
        .shell {
          grid-template-columns: 1fr;
        }

        .sidebar {
          border-right: 0;
          border-bottom: 1px solid var(--line);
        }

        .grid-2 {
          grid-template-columns: 1fr;
        }
      }
    </style>
  </head>
  <body>
    <div class="shell">
      <aside class="sidebar stack">
        <div class="brand">
          <h1>proxy-ops</h1>
          <p>Операторская панель для мониторинга, инцидентов и ручного remediation по всей прокси-площадке.</p>
        </div>

        <div class="token-box stack">
          <div>
            <label for="token-input">Admin Token</label>
            <input id="token-input" type="password" placeholder="Bearer token" />
          </div>
          <div class="row">
            <button id="save-token">Сохранить</button>
            <button id="clear-token" class="secondary">Очистить</button>
          </div>
          <div class="status-line" id="auth-status">Токен не задан</div>
        </div>

        <div class="project-list stack">
          <div class="row">
            <label style="margin:0">Проекты</label>
            <button id="refresh-projects" class="ghost">Обновить</button>
          </div>
          <div id="project-items" class="stack"></div>
        </div>
      </aside>

      <main class="main">
        <section class="panel hero">
          <div>
            <h2 id="hero-title">Выберите проект</h2>
            <p id="hero-subtitle">Панель работает поверх текущего Worker API и не требует отдельного backend.</p>
          </div>
          <div class="toolbar">
            <button id="refresh-current" class="secondary">Обновить проект</button>
            <button id="run-sweep" class="secondary">Run Sweep</button>
          </div>
        </section>

        <section class="panel metric-grid" id="metrics"></section>

        <div class="grid-2">
          <section class="section">
            <h3>Ноды и каналы</h3>
            <div id="nodes-list" class="stack"></div>
            <div id="channels-list" class="stack" style="margin-top:12px"></div>
          </section>

          <section class="section">
            <h3>Инциденты</h3>
            <div id="incidents-list" class="stack"></div>
          </section>
        </div>

        <section class="section">
          <h3>Действия</h3>
          <div id="actions-list" class="stack"></div>
        </section>

        <section class="section">
          <h3>План / ответ API</h3>
          <textarea id="details-box" readonly></textarea>
        </section>
      </main>
    </div>

    <div id="toast" class="toast"></div>

    <script type="module">
      const state = {
        token: localStorage.getItem('proxy_ops_admin_token') || '',
        projects: [],
        selectedProject: null,
        status: null,
        incidents: [],
        actions: [],
        capabilities: [],
      };

      const tokenInput = document.getElementById('token-input');
      const authStatus = document.getElementById('auth-status');
      const projectItems = document.getElementById('project-items');
      const heroTitle = document.getElementById('hero-title');
      const heroSubtitle = document.getElementById('hero-subtitle');
      const metrics = document.getElementById('metrics');
      const nodesList = document.getElementById('nodes-list');
      const channelsList = document.getElementById('channels-list');
      const incidentsList = document.getElementById('incidents-list');
      const actionsList = document.getElementById('actions-list');
      const detailsBox = document.getElementById('details-box');
      const toast = document.getElementById('toast');

      tokenInput.value = state.token;
      renderAuthState();

      document.getElementById('save-token').addEventListener('click', async () => {
        state.token = tokenInput.value.trim();
        localStorage.setItem('proxy_ops_admin_token', state.token);
        renderAuthState();
        await loadProjects();
      });

      document.getElementById('clear-token').addEventListener('click', () => {
        state.token = '';
        tokenInput.value = '';
        localStorage.removeItem('proxy_ops_admin_token');
        state.projects = [];
        state.selectedProject = null;
        state.status = null;
        state.incidents = [];
        state.actions = [];
        state.capabilities = [];
        renderAuthState();
        renderProjects();
        renderProject();
      });

      document.getElementById('refresh-projects').addEventListener('click', loadProjects);
      document.getElementById('refresh-current').addEventListener('click', async () => {
        if (state.selectedProject) await loadProject(state.selectedProject);
      });

      document.getElementById('run-sweep').addEventListener('click', async () => {
        if (!state.selectedProject) return;
        await runSweep(state.selectedProject);
      });

      loadProjects();

      async function api(path, init = {}) {
        if (!state.token) throw new Error('Admin token is required');
        const headers = new Headers(init.headers || {});
        headers.set('Authorization', 'Bearer ' + state.token);
        if (init.body && !headers.has('Content-Type')) {
          headers.set('Content-Type', 'application/json');
        }
        const response = await fetch(path, { ...init, headers });
        const text = await response.text();
        let payload = {};
        try {
          payload = text ? JSON.parse(text) : {};
        } catch {
          throw new Error('Non-JSON response: ' + text);
        }
        if (!response.ok || payload.ok === false) {
          const error = payload.error || {};
          throw new Error(error.message || error.code || ('HTTP ' + response.status));
        }
        return payload;
      }

      async function loadProjects() {
        if (!state.token) {
          renderProjects();
          renderProject();
          return;
        }
        try {
          const payload = await api('/v1/admin/projects');
          state.projects = payload.projects || [];
          if (!state.selectedProject && state.projects.length) {
            state.selectedProject = state.projects[0].slug;
          }
          if (state.selectedProject && !state.projects.find((item) => item.slug === state.selectedProject)) {
            state.selectedProject = state.projects.length ? state.projects[0].slug : null;
          }
          renderProjects();
          if (state.selectedProject) {
            await loadProject(state.selectedProject);
          } else {
            renderProject();
          }
          renderAuthState();
        } catch (error) {
          renderAuthState(error.message);
          showToast(error.message, true);
        }
      }

      async function loadProject(projectSlug) {
        state.selectedProject = projectSlug;
        renderProjects();
        try {
          const [statusPayload, incidentsPayload, actionsPayload, capabilitiesPayload] = await Promise.all([
            api('/v1/admin/projects/' + encodeURIComponent(projectSlug) + '/status'),
            api('/v1/admin/incidents?project=' + encodeURIComponent(projectSlug)),
            api('/v1/admin/actions?project=' + encodeURIComponent(projectSlug)),
            api('/v1/admin/node-capabilities?project=' + encodeURIComponent(projectSlug)),
          ]);
          state.status = statusPayload;
          state.incidents = incidentsPayload.incidents || [];
          state.actions = actionsPayload.actions || [];
          state.capabilities = capabilitiesPayload.capabilities || [];
          renderProject();
        } catch (error) {
          showToast(error.message, true);
        }
      }

      async function runSweep(projectSlug) {
        try {
          const payload = await api('/v1/admin/sweeps/run', {
            method: 'POST',
            body: JSON.stringify({ projectSlug }),
          });
          setDetails(payload);
          showToast('Sweep выполнен');
          await loadProject(projectSlug);
        } catch (error) {
          showToast(error.message, true);
        }
      }

      function renderAuthState(error) {
        if (!state.token) {
          authStatus.textContent = 'Токен не задан';
          return;
        }
        authStatus.textContent = error ? 'Ошибка авторизации: ' + error : 'Токен сохранён в localStorage браузера';
      }

      function renderProjects() {
        if (!state.projects.length) {
          projectItems.innerHTML = '<div class="empty">Нет доступных проектов</div>';
          return;
        }
        projectItems.innerHTML = state.projects.map((project) => {
          const active = project.slug === state.selectedProject ? ' active' : '';
          return '<button class="project-item' + active + '" data-project="' + escapeHtml(project.slug) + '">' +
            '<h3>' + escapeHtml(project.name) + '</h3>' +
            '<p class="mono">' + escapeHtml(project.slug) + '</p>' +
            '<p>overall: ' + renderStatusText(project.overall) + '</p>' +
            '<p>nodes: ' + project.nodeCount + ' · channels: ' + project.channelCount + '</p>' +
            '<p>open incidents: ' + project.openIncidentCount + '</p>' +
          '</button>';
        }).join('');

        projectItems.querySelectorAll('[data-project]').forEach((button) => {
          button.addEventListener('click', () => loadProject(button.dataset.project));
        });
      }

      function renderProject() {
        if (!state.status) {
          heroTitle.textContent = 'Выберите проект';
          heroSubtitle.textContent = 'После выбора проекта здесь появятся статус, инциденты и действия.';
          metrics.innerHTML = '';
          nodesList.innerHTML = '<div class="empty">Нет данных</div>';
          channelsList.innerHTML = '';
          incidentsList.innerHTML = '<div class="empty">Нет данных</div>';
          actionsList.innerHTML = '<div class="empty">Нет данных</div>';
          return;
        }

        const project = state.status.project;
        heroTitle.textContent = project.name;
        heroSubtitle.innerHTML = '<span class="mono">' + escapeHtml(project.slug) + '</span> · ' +
          '<span class="badge ' + badgeClass(state.status.overall) + '">' + escapeHtml(renderStatusText(state.status.overall)) + '</span>';

        const openIncidents = state.incidents.filter((incident) => incident.status === 'open').length;
        metrics.innerHTML =
          renderMetric('Overall', state.status.overall) +
          renderMetric('Nodes', String(state.status.nodes.length)) +
          renderMetric('Channels', String(state.status.channels.length)) +
          renderMetric('Open Incidents', String(openIncidents));

        nodesList.innerHTML = state.status.nodes.length
          ? state.status.nodes.map((node) => {
              return '<div class="item-card">' +
                '<h4>' + escapeHtml(node.name || node.slug) + '</h4>' +
                '<div class="meta mono">' + escapeHtml(node.slug) + '</div>' +
                '<div class="meta">status: <span class="badge ' + badgeClass(node.status) + '">' + escapeHtml(renderStatusText(node.status)) + '</span></div>' +
                '<div class="meta">host: ' + escapeHtml(node.hostname || '-') + '</div>' +
                '<div class="meta">region: ' + escapeHtml(node.region || '-') + '</div>' +
                '<div class="meta">last heartbeat: ' + escapeHtml(formatTime(node.last_heartbeat_at)) + '</div>' +
              '</div>';
            }).join('')
          : '<div class="empty">Нет нод</div>';

        channelsList.innerHTML = state.status.channels.length
          ? state.status.channels.map((channel) => {
              return '<div class="item-card">' +
                '<h4>' + escapeHtml(channel.name || channel.slug) + '</h4>' +
                '<div class="meta mono">' + escapeHtml(channel.slug) + ' · ' + escapeHtml(channel.protocol) + '</div>' +
                '<div class="meta">target: ' + escapeHtml(channel.target) + '</div>' +
                '<div class="meta">status: <span class="badge ' + badgeClass(channel.status) + '">' + escapeHtml(renderStatusText(channel.status)) + '</span></div>' +
                '<div class="meta">last check: ' + escapeHtml(formatTime(channel.last_checked_at)) + '</div>' +
                '<div class="meta">failures: ' + escapeHtml(String(channel.consecutive_failures || 0)) + '</div>' +
              '</div>';
            }).join('')
          : '<div class="empty">Нет каналов</div>';

        renderIncidents();
        renderActions();
      }

      function renderIncidents() {
        if (!state.incidents.length) {
          incidentsList.innerHTML = '<div class="empty">Инцидентов нет</div>';
          return;
        }
        incidentsList.innerHTML = state.incidents.map((incident) => {
          const services = collectServiceOptions();
          const serviceOptions = services.map((service) => '<option value="' + escapeHtml(service) + '">' + escapeHtml(service) + '</option>').join('');
          return '<div class="item-card">' +
            '<h4>' + escapeHtml(incident.title || incident.kind) + '</h4>' +
            '<div class="meta mono">' + escapeHtml(incident.id) + '</div>' +
            '<div class="meta">status: <span class="badge ' + badgeClass(incident.status) + '">' + escapeHtml(renderStatusText(incident.status)) + '</span></div>' +
            '<div class="meta">severity: <span class="badge ' + badgeClass(incident.severity) + '">' + escapeHtml(renderStatusText(incident.severity)) + '</span></div>' +
            '<div class="meta">summary: ' + escapeHtml(incident.summary || '-') + '</div>' +
            '<div class="meta">last seen: ' + escapeHtml(formatTime(incident.last_seen_at)) + '</div>' +
            '<div class="actions">' +
              '<button data-ai="' + escapeHtml(incident.id) + '" class="secondary">AI Analyze</button>' +
              '<button data-plan="' + escapeHtml(incident.id) + '" class="secondary">Plan</button>' +
              '<button data-diag="' + escapeHtml(incident.id) + '">Collect Diagnostics</button>' +
              '<button data-resolve="' + escapeHtml(incident.id) + '" class="warn">Resolve</button>' +
            '</div>' +
            '<div class="row" style="margin-top:12px">' +
              '<select data-restart-service="' + escapeHtml(incident.id) + '">' + serviceOptions + '</select>' +
              '<button data-restart="' + escapeHtml(incident.id) + '" class="danger">Restart Service</button>' +
              '<button data-reload="' + escapeHtml(incident.id) + '" class="secondary">Reload Service</button>' +
            '</div>' +
            (incident.ai_summary ? '<div class="meta" style="margin-top:12px"><strong>AI:</strong><br />' + escapeHtml(incident.ai_summary) + '</div>' : '') +
          '</div>';
        }).join('');

        bindIncidentButtons();
      }

      function renderActions() {
        if (!state.actions.length) {
          actionsList.innerHTML = '<div class="empty">Действий нет</div>';
          return;
        }
        actionsList.innerHTML = state.actions.map((action) => {
          return '<div class="item-card">' +
            '<h4>' + escapeHtml(action.runbookTitle || action.runbookSlug) + '</h4>' +
            '<div class="meta mono">' + escapeHtml(action.id) + '</div>' +
            '<div class="meta">status: <span class="badge ' + badgeClass(action.status) + '">' + escapeHtml(renderStatusText(action.status)) + '</span></div>' +
            '<div class="meta">approval: <span class="badge ' + badgeClass(action.approvalStatus) + '">' + escapeHtml(renderStatusText(action.approvalStatus)) + '</span></div>' +
            '<div class="meta">node: ' + escapeHtml(action.nodeSlug || '-') + '</div>' +
            '<div class="meta">params: <span class="mono">' + escapeHtml(JSON.stringify(action.params || {})) + '</span></div>' +
            '<div class="meta">result: ' + escapeHtml(action.resultSummary || '-') + '</div>' +
            '<div class="actions">' +
              (action.status === 'pending' ? '<button data-approve="' + escapeHtml(action.id) + '">Approve</button>' : '') +
              ((action.status === 'pending' || action.status === 'queued' || action.status === 'leased' || action.status === 'running') ? '<button data-cancel="' + escapeHtml(action.id) + '" class="danger">Cancel</button>' : '') +
              '<button data-action-events="' + escapeHtml(action.id) + '" class="secondary">Events</button>' +
            '</div>' +
          '</div>';
        }).join('');

        bindActionButtons();
      }

      function bindIncidentButtons() {
        incidentsList.querySelectorAll('[data-ai]').forEach((button) => {
          button.addEventListener('click', async () => runSimpleAction('/v1/admin/incidents/' + button.dataset.ai + '/ai-analyze'));
        });
        incidentsList.querySelectorAll('[data-plan]').forEach((button) => {
          button.addEventListener('click', async () => runSimpleAction('/v1/admin/incidents/' + button.dataset.plan + '/remediation/plan'));
        });
        incidentsList.querySelectorAll('[data-diag]').forEach((button) => {
          button.addEventListener('click', async () => createAction(button.dataset.diag, 'collect-diagnostics', {}));
        });
        incidentsList.querySelectorAll('[data-resolve]').forEach((button) => {
          button.addEventListener('click', async () => runSimpleAction('/v1/admin/incidents/' + button.dataset.resolve + '/resolve', { method: 'POST' }));
        });
        incidentsList.querySelectorAll('[data-restart]').forEach((button) => {
          button.addEventListener('click', async () => {
            const select = incidentsList.querySelector('[data-restart-service="' + button.dataset.restart + '"]');
            await createAction(button.dataset.restart, 'restart-service', { service: select.value });
          });
        });
        incidentsList.querySelectorAll('[data-reload]').forEach((button) => {
          button.addEventListener('click', async () => {
            const select = incidentsList.querySelector('[data-restart-service="' + button.dataset.reload + '"]');
            await createAction(button.dataset.reload, 'reload-service', { service: select.value });
          });
        });
      }

      function bindActionButtons() {
        actionsList.querySelectorAll('[data-approve]').forEach((button) => {
          button.addEventListener('click', async () => runSimpleAction('/v1/admin/actions/' + button.dataset.approve + '/approve', {
            method: 'POST',
            body: JSON.stringify({ by: 'web-ui', note: 'approved from operator panel' }),
          }));
        });
        actionsList.querySelectorAll('[data-cancel]').forEach((button) => {
          button.addEventListener('click', async () => runSimpleAction('/v1/admin/actions/' + button.dataset.cancel + '/cancel', {
            method: 'POST',
            body: JSON.stringify({ by: 'web-ui', reason: 'canceled from operator panel' }),
          }));
        });
        actionsList.querySelectorAll('[data-action-events]').forEach((button) => {
          button.addEventListener('click', async () => runSimpleAction('/v1/admin/actions/' + button.dataset.actionEvents + '/events'));
        });
      }

      async function createAction(incidentId, runbookSlug, params) {
        try {
          const payload = await api('/v1/admin/incidents/' + incidentId + '/remediation/actions', {
            method: 'POST',
            body: JSON.stringify({ runbookSlug, params }),
          });
          setDetails(payload);
          showToast('Action создан');
          await loadProject(state.selectedProject);
        } catch (error) {
          showToast(error.message, true);
        }
      }

      async function runSimpleAction(path, init) {
        try {
          const payload = await api(path, init || { method: 'POST' });
          setDetails(payload);
          showToast('Операция выполнена');
          await loadProject(state.selectedProject);
        } catch (error) {
          showToast(error.message, true);
        }
      }

      function collectServiceOptions() {
        const options = new Set();
        for (const capability of state.capabilities) {
          if (capability.actionType !== 'restart_service' && capability.actionType !== 'reload_service') continue;
          const services = Array.isArray(capability.config && capability.config.services) ? capability.config.services : [];
          for (const service of services) options.add(service);
        }
        return Array.from(options).sort();
      }

      function renderMetric(label, value) {
        return '<div class="metric"><span>' + escapeHtml(label) + '</span><strong>' + escapeHtml(value) + '</strong></div>';
      }

      function setDetails(payload) {
        detailsBox.value = JSON.stringify(payload, null, 2);
      }

      function badgeClass(value) {
        const raw = String(value || '').toLowerCase();
        if (['healthy', 'resolved', 'succeeded', 'not_required', 'approved', 'pass', 'ok'].includes(raw)) return 'healthy';
        if (['critical', 'failed', 'rejected', 'canceled', 'fail'].includes(raw)) return 'critical';
        if (['degraded', 'warning'].includes(raw)) return 'warning';
        if (['pending', 'queued', 'leased', 'running'].includes(raw)) return 'pending';
        return 'healthy';
      }

      function renderStatusText(value) {
        return String(value || '-').replaceAll('_', ' ');
      }

      function formatTime(value) {
        if (!value) return '-';
        try {
          return new Date(value).toLocaleString('ru-RU', { hour12: false });
        } catch {
          return value;
        }
      }

      function escapeHtml(value) {
        return String(value ?? '')
          .replaceAll('&', '&amp;')
          .replaceAll('<', '&lt;')
          .replaceAll('>', '&gt;')
          .replaceAll('"', '&quot;')
          .replaceAll("'", '&#39;');
      }

      let toastTimer = null;
      function showToast(message, isError) {
        toast.textContent = (isError ? 'Ошибка: ' : '') + message;
        toast.classList.add('visible');
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => toast.classList.remove('visible'), 2600);
      }
    </script>
  </body>
</html>`;
}
