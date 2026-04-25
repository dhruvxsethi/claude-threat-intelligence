function setText(id, v) { const el = document.getElementById(id); if (el) el.textContent = v; }

async function loadFeeds() {
  const d = await fetch('/api/feeds').then(r => r.json());
  const feeds  = d.health || [];
  const runs   = d.recentRuns || [];

  const healthy = feeds.filter(f => f.is_healthy).length;
  const failed  = feeds.filter(f => !f.is_healthy).length;
  setText('feeds-healthy', healthy);
  setText('feeds-failed',  failed);
  setText('feeds-total',   feeds.length);
  const today = new Date().toDateString();
  setText('runs-today', runs.filter(r => new Date(r.started_at).toDateString() === today).length);

  renderHealth(feeds);
  renderRuns(runs);
}

// Group feeds by type (API vs RSS tier)
function feedGroup(f) {
  const name = (f.feed_name || f.feed_id || '').toLowerCase();
  if (name.includes('nvd') || name.includes('cisa') || name.includes('github advisory')) return 'Vulnerability APIs';
  if ((f.tier || '') === '1' || name.includes('mandiant') || name.includes('crowdstrike') || name.includes('recorded future') || name.includes('unit 42') || name.includes('talos') || name.includes('microsoft') || name.includes('google')) return 'Tier 1 — Vendor Research';
  if ((f.tier || '') === '2') return 'Tier 2 — Security News';
  return 'Other';
}

const GROUP_ORDER = ['Vulnerability APIs', 'Tier 1 — Vendor Research', 'Tier 2 — Security News', 'Other'];

function renderHealth(feeds) {
  const el = document.getElementById('feed-health-list');
  if (!feeds.length) {
    el.innerHTML = '<div class="text-sm text-3" style="padding:16px">No feed data yet — run the pipeline first.</div>';
    return;
  }

  // Group
  const groups = {};
  for (const f of feeds) {
    const g = feedGroup(f);
    if (!groups[g]) groups[g] = [];
    groups[g].push(f);
  }

  let html = '';
  for (const gName of GROUP_ORDER) {
    const items = groups[gName];
    if (!items?.length) continue;
    html += `<div class="feed-group-label">${gName}</div>`;
    html += items.map(f => {
      const ok = f.is_healthy;
      const fails = f.consecutive_failures || 0;
      return `<div class="feed-item">
        <div class="feed-dot ${ok ? 'ok' : 'err'}"></div>
        <span class="feed-name">${esc(f.feed_name || f.feed_id)}</span>
        <span class="feed-count">${f.total_threats_contributed || 0} threats</span>
        <span class="text-xs text-3">${f.last_success ? relTime(f.last_success) : 'never'}</span>
        ${!ok && fails > 0 ? `<span class="badge badge-critical" style="font-size:.65rem">${fails} fail${fails !== 1 ? 's' : ''}</span>` : ''}
      </div>`;
    }).join('');
  }
  el.innerHTML = html;
}

function renderRuns(runs) {
  const el = document.getElementById('recent-runs');
  if (!runs.length) {
    el.innerHTML = '<div class="text-sm text-3" style="padding:16px">No runs yet.</div>';
    return;
  }
  el.innerHTML = `<div class="table-wrap"><table class="data-table">
    <thead><tr>
      <th>Feed</th><th>Status</th><th>Fetched</th><th>New</th><th>Threats</th><th>Started</th>
    </tr></thead>
    <tbody>${runs.map(r => `<tr>
      <td class="text-sm">${esc(r.feed_name || r.feed_id)}</td>
      <td><span class="badge badge-${r.status === 'success' ? 'low' : r.status === 'failed' ? 'critical' : r.status === 'running' ? 'medium' : 'unknown'}">${r.status}</span></td>
      <td class="text-xs mono">${r.articles_fetched || 0}</td>
      <td class="text-xs mono">${r.articles_new || 0}</td>
      <td class="text-xs mono" style="color:var(--low)">${r.threats_created || 0}</td>
      <td class="text-xs text-3">${relTime(r.started_at)}</td>
    </tr>`).join('')}</tbody>
  </table></div>`;
}

loadFeeds();
setInterval(loadFeeds, 15000);
connectSse(null, loadFeeds);
