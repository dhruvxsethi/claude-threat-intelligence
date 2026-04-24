// Feed Health page

async function loadFeeds() {
  const res = await fetch('/api/feeds');
  const data = await res.json();

  const healthy = data.health?.filter(f => f.is_healthy).length || 0;
  const failed = data.health?.filter(f => !f.is_healthy).length || 0;
  document.getElementById('feeds-healthy').textContent = healthy;
  document.getElementById('feeds-failed').textContent = failed;
  document.getElementById('feeds-total').textContent = data.health?.length || 0;

  const today = new Date().toDateString();
  const runsToday = data.recentRuns?.filter(r => new Date(r.started_at).toDateString() === today).length || 0;
  document.getElementById('runs-today').textContent = runsToday;

  renderFeedHealth(data.health || []);
  renderRecentRuns(data.recentRuns || []);
}

function renderFeedHealth(feeds) {
  const el = document.getElementById('feed-health-list');
  if (!feeds.length) { el.innerHTML = '<div class="text-muted text-sm" style="padding:12px">No feed data yet. Run the pipeline first.</div>'; return; }

  el.innerHTML = feeds.map(f => `
    <div class="feed-item">
      <div class="feed-status ${f.is_healthy ? 'ok' : 'error'}"></div>
      <span class="feed-name">${f.feed_name || f.feed_id}</span>
      <span class="feed-count">${f.total_threats_contributed || 0} threats</span>
      <span class="text-xs text-muted">${f.last_success ? relativeTime(f.last_success) : 'never'}</span>
      ${!f.is_healthy ? `<span class="badge badge-critical" style="font-size:0.65rem">${f.consecutive_failures} fails</span>` : ''}
    </div>
  `).join('');
}

function renderRecentRuns(runs) {
  const el = document.getElementById('recent-runs');
  if (!runs.length) { el.innerHTML = '<div class="text-muted text-sm" style="padding:12px">No runs yet.</div>'; return; }

  el.innerHTML = `
    <table class="threat-table">
      <thead><tr>
        <th>Feed</th><th>Slot</th><th>Status</th><th>Fetched</th><th>New</th><th>Analyzed</th><th>Threats</th><th>Started</th>
      </tr></thead>
      <tbody>
        ${runs.map(r => `
          <tr>
            <td class="text-sm">${r.feed_name || r.feed_id}</td>
            <td><span class="badge badge-unknown">${r.slot || '?'}</span></td>
            <td>
              <span class="badge ${r.status === 'success' ? 'badge-low' : r.status === 'failed' ? 'badge-critical' : r.status === 'running' ? 'badge-medium' : 'badge-unknown'}">${r.status}</span>
            </td>
            <td class="text-xs font-mono">${r.articles_fetched || 0}</td>
            <td class="text-xs font-mono">${r.articles_new || 0}</td>
            <td class="text-xs font-mono">${r.articles_analyzed || 0}</td>
            <td class="text-xs font-mono" style="color:var(--low)">${r.threats_created || 0}</td>
            <td class="text-xs text-muted">${relativeTime(r.started_at)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

loadFeeds();
setInterval(loadFeeds, 15000);
connectSse(null, loadFeeds);
