function setText(id, v) { const el = document.getElementById(id); if (el) el.textContent = v; }

async function loadFeeds() {
  const d = await fetch('/api/feeds').then(r => r.json());
  const feeds  = d.health || [];
  const runs   = d.recentRuns || [];

  const active   = feeds.filter(f => f.enabled !== false);
  const healthy  = active.filter(f => f.is_healthy).length;
  const failed   = active.filter(f => f.is_healthy === 0 && !f.never_run).length;
  setText('feeds-healthy', healthy);
  setText('feeds-failed',  failed);
  setText('feeds-total',   active.length);
  const today = new Date().toDateString();
  setText('runs-today', runs.filter(r => new Date(r.started_at).toDateString() === today).length);

  renderHealth(feeds);
  renderRuns(runs);
}

// Group feeds by tier/type
function feedGroup(f) {
  if (f.enabled === false) return 'Disabled';
  const name = (f.feed_name || f.feed_id || '').toLowerCase();
  const tier = f.tier;
  if (name.includes('nvd') || name.includes('cisa') || name.includes('github advisor')) return 'Vulnerability APIs';
  if (tier === 1 || tier === '1') return 'Tier 1 — Official & Major Vendors';
  if (tier === 2 || tier === '2') return 'Tier 2 — Major Vendors';
  if (tier === 3 || tier === '3') return 'Tier 3 — Security News';
  if (tier === 4 || tier === '4') return 'Tier 4 — Sector-Specific';
  if (tier === 5 || tier === '5') return 'Tier 5 — Community';
  return 'Other';
}

const GROUP_ORDER = [
  'Vulnerability APIs',
  'Tier 1 — Official & Major Vendors',
  'Tier 2 — Major Vendors',
  'Tier 3 — Security News',
  'Tier 4 — Sector-Specific',
  'Tier 5 — Community',
  'Other',
  'Disabled',
];

function feedDotClass(f) {
  if (f.enabled === false) return 'disabled';
  if (f.never_run) return 'never';
  return f.is_healthy ? 'ok' : 'err';
}

function renderHealth(feeds) {
  const el = document.getElementById('feed-health-list');
  if (!feeds.length) {
    el.innerHTML = '<div class="text-sm text-3" style="padding:16px">No feed data yet — run the pipeline first.</div>';
    return;
  }

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
    const isDisabled = gName === 'Disabled';
    html += `<div class="feed-group-label">${gName}${isDisabled ? ' — excluded from pipeline' : ''}</div>`;
    html += items.map(f => {
      const dotCls = feedDotClass(f);
      const fails = f.consecutive_failures || 0;
      const statusBadge = f.enabled === false
        ? `<span class="badge badge-unknown" style="font-size:.6rem">disabled</span>`
        : f.never_run
          ? `<span class="text-xs text-3">never run</span>`
          : (!f.is_healthy && fails > 0)
            ? `<span class="badge badge-critical" style="font-size:.6rem">${fails} fail${fails !== 1 ? 's' : ''}</span>`
            : '';
      return `<div class="feed-item" style="${f.enabled === false ? 'opacity:.45' : ''}">
        <div class="feed-dot ${dotCls}"></div>
        <div class="feed-info">
          <div class="feed-name">${esc(f.feed_name || f.feed_id)}</div>
          <div class="feed-meta">${f.articles_seen || 0} seen · ${f.articles_processed || 0} processed · ${f.articles_skipped || 0} skipped</div>
        </div>
        <span class="feed-count">${f.computed_threats ?? f.total_threats_contributed ?? 0} threats</span>
        <span class="feed-time">${f.last_success ? relTime(f.last_success) : '—'}</span>
        ${statusBadge}
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
