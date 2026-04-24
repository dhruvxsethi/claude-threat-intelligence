async function loadStats() {
  const d = await fetch('/api/stats?days=7').then(r=>r.json());

  const bySev = {};
  (d.by_severity||[]).forEach(s => bySev[s.severity] = s.cnt);
  setText('s-critical', bySev.critical||0);
  setText('s-high', bySev.high||0);
  setText('s-medium', bySev.medium||0);
  setText('s-today', d.summary?.today_count||0);
  setText('s-cves', d.summary?.cve_count||0);
  setText('s-kev', `${d.summary?.kev_count||0} in CISA KEV`);
  setText('s-iocs', d.summary?.ioc_count||0);
  setText('s-feeds', d.summary?.feeds_active||0);
  setText('s-total', d.summary?.total||0);

  (d.sector_stats||[]).forEach(s => setText(`sec-${s.sector}`, s.count));

  renderCharts(d);
  renderCriticalCves(d.critical_cves||[]);
  renderTopActors(d.top_actors||[]);
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

async function loadLatest() {
  const d = await fetch('/api/threats?limit=12&sort=ingested_at&order=desc&days=7').then(r=>r.json());
  const el = document.getElementById('latest-threats');
  if (!el) return;
  if (!d.threats?.length) return;

  el.innerHTML = `<div class="table-wrap"><table class="data-table" style="margin:-22px -24px;width:calc(100% + 48px)">
    <thead><tr>
      <th>Severity</th><th>Threat</th><th>Sectors</th><th>Type</th><th>Confidence</th><th>Age</th>
    </tr></thead>
    <tbody>${d.threats.map(t=>`<tr>
      <td>${sevBadge(t.severity)}</td>
      <td class="cell-title"><a href="/threat-detail.html?id=${t.id}">${esc(t.title)}</a><div class="cell-sub">${esc(t.source_name||'')}</div></td>
      <td>${(t.sectors||[]).map(secBadge).join(' ')}</td>
      <td><span class="text-xs text-2">${typeLabel(t.threat_type)}</span></td>
      <td>${credBar(t.credibility_score)}</td>
      <td class="text-xs text-3">${relTime(t.ingested_at)}</td>
    </tr>`).join('')}</tbody>
  </table></div>`;
}

function renderCriticalCves(cves) {
  const el = document.getElementById('critical-cves');
  if (!el || !cves.length) return;
  el.innerHTML = cves.map(c=>`<div class="cve-card">
    <div class="flex items-center gap-2 mb-2">
      <a class="cve-id" href="/threat-detail.html?id=${c.threat_id}">${c.cve_id}</a>
      <span class="cvss-chip" style="background:var(--crit-dim);color:var(--critical)">${c.cvss_score}</span>
      <span class="badge badge-critical">Critical</span>
    </div>
    <div class="cve-desc">${esc((c.title||'').slice(0,80))}…</div>
  </div>`).join('');
}

function renderTopActors(actors) {
  const el = document.getElementById('top-actors');
  if (!el || !actors.length) return;
  el.innerHTML = actors.map(a=>`<div class="actor-card">
    <div class="actor-name">${esc(a.name)}</div>
    <div class="actor-meta">${a.cnt} threat${a.cnt!==1?'s':''} in 7 days</div>
  </div>`).join('');
}

loadStats();
loadLatest();
setInterval(() => { loadStats(); loadLatest(); }, 30000);
connectSse(null, () => { loadStats(); loadLatest(); });
