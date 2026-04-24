// Dashboard page logic

async function loadStats() {
  const res = await fetch('/api/stats?days=7');
  const data = await res.json();

  // Stat cards
  const bySev = {};
  data.by_severity?.forEach(s => bySev[s.severity] = s.cnt);
  document.getElementById('stat-critical').textContent = bySev.critical || 0;
  document.getElementById('stat-high').textContent = bySev.high || 0;
  document.getElementById('stat-medium').textContent = bySev.medium || 0;
  document.getElementById('stat-today').textContent = data.summary?.today_count || 0;
  document.getElementById('stat-cves').textContent = data.summary?.cve_count || 0;
  document.getElementById('stat-kev').textContent = data.summary?.kev_count || 0;
  document.getElementById('stat-iocs').textContent = data.summary?.ioc_count || 0;
  document.getElementById('stat-feeds').textContent = data.summary?.feeds_active || 0;

  // Sector counts
  data.sector_stats?.forEach(s => {
    const el = document.getElementById(`sec-${s.sector}`);
    if (el) el.textContent = s.count;
  });

  // Charts
  renderCharts(data);

  // Critical CVEs
  renderCriticalCves(data.critical_cves || []);

  // Top actors
  renderTopActors(data.top_actors || []);
}

async function loadLatestThreats() {
  const res = await fetch('/api/threats?limit=10&sort=ingested_at&order=desc&days=7');
  const data = await res.json();

  const tbody = document.getElementById('latest-threats');
  if (!data.threats?.length) return;

  tbody.innerHTML = `
    <table class="threat-table" style="margin:-20px;width:calc(100% + 40px)">
      <thead>
        <tr>
          <th>Severity</th>
          <th>Threat</th>
          <th>Sectors</th>
          <th>Type</th>
          <th>Confidence</th>
          <th>Age</th>
        </tr>
      </thead>
      <tbody>
        ${data.threats.map(t => `
          <tr>
            <td>${severityBadge(t.severity)}</td>
            <td>
              <a class="threat-title-link" href="/threat-detail.html?id=${t.id}">${t.title}</a>
              <div class="threat-meta">${t.source_name}</div>
            </td>
            <td>${(t.sectors || []).map(sectorBadge).join(' ')}</td>
            <td><span class="text-xs text-dim">${threatTypeLabel(t.threat_type)}</span></td>
            <td>
              <div class="flex gap-2 items-center">
                ${credBar(t.credibility_score)}
              </div>
            </td>
            <td class="text-muted text-xs">${relativeTime(t.ingested_at)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

function renderCriticalCves(cves) {
  const el = document.getElementById('critical-cves');
  if (!cves.length) return;
  el.innerHTML = cves.map(c => `
    <div class="cve-card">
      <div class="cve-header">
        <a class="cve-id" href="/threat-detail.html?id=${c.threat_id}">${c.cve_id}</a>
        <span class="cvss-score" style="background:var(--critical-bg);color:var(--critical);font-size:0.8rem;padding:2px 8px;border-radius:4px">${c.cvss_score}</span>
        <span class="badge badge-critical">KEV Risk</span>
      </div>
      <div class="cve-desc text-xs text-muted">${c.title?.slice(0, 80)}...</div>
    </div>
  `).join('');
}

function renderTopActors(actors) {
  const el = document.getElementById('top-actors');
  if (!actors.length) return;
  el.innerHTML = actors.map(a => `
    <div class="actor-card">
      <div class="actor-name">${a.name}</div>
      <div class="actor-meta">${a.cnt} threat${a.cnt !== 1 ? 's' : ''} in 7 days</div>
    </div>
  `).join('');
}

// Init
loadStats();
loadLatestThreats();
setInterval(loadStats, 30000);

// SSE
connectSse(null, () => {
  loadStats();
  loadLatestThreats();
});
