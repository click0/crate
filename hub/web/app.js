// crate-hub dashboard — vanilla JS (no bundler, no framework).
//
// Polls the hub's read-only F1 endpoints and renders a table view.
// Mutating actions (start/stop/restart) call the *daemon's* F2 API
// directly and need an admin Bearer token, which the user pastes
// into the local-storage prompt the first time they click Action.
//
// Endpoints used:
//   GET  /api/v1/aggregate          — summary banner
//   GET  /api/v1/nodes              — node list with reachability
//   GET  /api/v1/containers         — containers grouped by node
//
// Mutation (proxied directly to crated; not via hub):
//   POST <node-host>/api/v1/containers/<name>/{start,stop,restart}
//   DELETE <node-host>/api/v1/containers/<name>

const REFRESH_MS = 5000;

const $ = (id) => document.getElementById(id);

document.getElementById('refresh-period').textContent =
  (REFRESH_MS / 1000) + 's';

// --- HTTP helpers ---

async function getJson(path) {
  const r = await fetch(path, { headers: { 'Accept': 'application/json' } });
  if (!r.ok) throw new Error(`${path} → ${r.status}`);
  const j = await r.json();
  if (j.status !== 'ok') throw new Error(j.error || 'unknown error');
  return j.data;
}

// Mutating actions hit the per-node daemon. The hub itself doesn't
// proxy POST so we can't carry the admin token through it.
function getAdminToken() {
  let t = localStorage.getItem('crate-admin-token');
  if (!t) {
    t = prompt('Paste an admin Bearer token (will be stored in localStorage):');
    if (!t) return null;
    localStorage.setItem('crate-admin-token', t);
  }
  return t;
}

async function nodeAction(nodeHost, name, verb) {
  const token = getAdminToken();
  if (!token) return;
  let url = `https://${nodeHost}/api/v1/containers/${encodeURIComponent(name)}/${verb}`;
  let method = 'POST';
  if (verb === 'destroy') {
    url = `https://${nodeHost}/api/v1/containers/${encodeURIComponent(name)}`;
    method = 'DELETE';
  }
  const r = await fetch(url, {
    method,
    headers: { 'Authorization': `Bearer ${token}` },
  });
  if (!r.ok) {
    alert(`${verb} failed: HTTP ${r.status}`);
    return;
  }
  // Force a fresh poll so the table reflects the new state.
  refresh();
}

// --- Renderers ---

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[c]);
}

function renderSummary(s) {
  $('nodes-total').textContent      = s.nodes_total;
  $('nodes-reachable').textContent  = s.nodes_reachable;
  $('nodes-down').textContent       = s.nodes_down;
  $('containers-total').textContent = s.containers_total;
}

function renderNodes(nodes) {
  const body = $('nodes-body');
  if (!nodes.length) {
    body.innerHTML = '<tr><td colspan="6" class="muted">No nodes configured</td></tr>';
    return;
  }
  body.innerHTML = nodes.map(n => `
    <tr>
      <td>${escapeHtml(n.name)}</td>
      <td>${escapeHtml(n.datacenter || 'default')}</td>
      <td><code>${escapeHtml(n.host)}</code></td>
      <td class="${n.reachable ? 'status-ok' : 'status-error'}">
        ${n.reachable ? 'reachable' : 'down'}
      </td>
      <td>—</td>
      <td class="muted">${n.error ? escapeHtml(n.error) : ''}</td>
    </tr>`).join('');
}

function renderDatacenters(dcs) {
  const body = $('datacenters-body');
  if (!dcs.length) {
    body.innerHTML = '<tr><td colspan="5" class="muted">No datacenters configured</td></tr>';
    return;
  }
  body.innerHTML = dcs.map(d => `
    <tr>
      <td><strong>${escapeHtml(d.name)}</strong></td>
      <td>${d.nodes_total}</td>
      <td class="status-ok">${d.nodes_reachable}</td>
      <td class="${d.nodes_down ? 'status-error' : 'muted'}">${d.nodes_down}</td>
      <td>${d.containers_total}</td>
    </tr>`).join('');
}

function renderContainers(grouped) {
  const body = $('containers-body');
  let rows = [];
  for (const g of grouped) {
    const nodeName = g.node;
    let containers = [];
    try {
      containers = JSON.parse(g.containers || '[]');
    } catch (_) { /* ignore */ }
    if (!Array.isArray(containers)) continue;
    for (const c of containers) {
      // Daemon returns whatever `jls --libxo json` produces; pull a
      // few common fields, fall back gracefully when missing.
      const host = c.host || c.hostname || c.name || '';
      const jid  = c.jid  || c.JID || '';
      const ip   = c.ip4  || c.ip   || c.IP || '';
      const name = c.name || c.host || c.hostname || '';
      rows.push(`
        <tr>
          <td>${escapeHtml(nodeName)}</td>
          <td>${escapeHtml(name)}</td>
          <td>${escapeHtml(jid)}</td>
          <td><code>${escapeHtml(ip)}</code></td>
          <td>
            <button data-name="${escapeHtml(name)}" data-verb="start">start</button>
            <button data-name="${escapeHtml(name)}" data-verb="stop">stop</button>
            <button data-name="${escapeHtml(name)}" data-verb="restart">restart</button>
            <button class="danger" data-name="${escapeHtml(name)}" data-verb="destroy">destroy</button>
          </td>
        </tr>`);
    }
  }
  body.innerHTML = rows.length
    ? rows.join('')
    : '<tr><td colspan="5" class="muted">No containers</td></tr>';
}

// Wire up button clicks via event delegation. The handler reads
// `data-name` / `data-verb` so renderContainers() doesn't have to
// register listeners per button.
document.addEventListener('click', (ev) => {
  const btn = ev.target.closest('button[data-verb]');
  if (!btn) return;
  // Find which node this row belongs to (first <td> in the row).
  const tr = btn.closest('tr');
  if (!tr) return;
  const nodeCell = tr.querySelector('td');
  if (!nodeCell) return;
  // Look up the host for that node by reading the nodes table.
  const wantedNode = nodeCell.textContent.trim();
  let host = null;
  for (const row of $('nodes-body').querySelectorAll('tr')) {
    const cells = row.querySelectorAll('td');
    if (cells.length >= 2 && cells[0].textContent.trim() === wantedNode) {
      host = cells[1].textContent.trim();
      break;
    }
  }
  if (!host) {
    alert(`Cannot find host for node '${wantedNode}'`);
    return;
  }
  if (btn.dataset.verb === 'destroy' &&
      !confirm(`Destroy ${btn.dataset.name} on ${wantedNode}? This is irreversible.`))
    return;
  nodeAction(host, btn.dataset.name, btn.dataset.verb);
});

// --- Main loop ---

async function refresh() {
  const ind = $('poll-indicator');
  try {
    const [agg, dcs, nodes, contGroups] = await Promise.all([
      getJson('/api/v1/aggregate'),
      getJson('/api/v1/datacenters'),
      getJson('/api/v1/nodes'),
      getJson('/api/v1/containers'),
    ]);
    renderSummary(agg);
    renderDatacenters(dcs);
    renderNodes(nodes);
    renderContainers(contGroups);
    ind.className = 'dot ok';
    ind.title = 'Last poll OK';
    $('last-update').textContent =
      'updated ' + new Date().toLocaleTimeString();
  } catch (err) {
    ind.className = 'dot error';
    ind.title = 'Poll failed: ' + err.message;
    $('last-update').textContent =
      'poll error: ' + err.message;
  }
}

refresh();
setInterval(refresh, REFRESH_MS);
