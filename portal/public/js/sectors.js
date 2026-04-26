let _sector='banking';

async function switchSector(s, btn) {
  _sector=s;
  document.querySelectorAll('.sector-tab').forEach(t=>t.classList.remove('active'));
  btn.classList.add('active');
  await loadSector(s);
}

async function loadSector(s) {
  document.getElementById('sector-content').innerHTML=`<div class="empty"><div class="empty-icon">⏳</div><div class="empty-title">Loading ${s}…</div></div>`;
  const d=await fetch(`/api/sectors/${s}?days=7`).then(r=>r.json());
  const icons={banking:'🏦',government:'🏛️',healthcare:'🏥'};

  const cvesHtml=d.topCves?.length?d.topCves.map(c=>`<div class="cve-card">
    <div class="flex items-center gap-2">
      <a class="cve-id" href="/threat-detail.html?id=${c.threat_id}">${c.cve_id}</a>
      ${c.cvss_score?`<span class="cvss-chip" style="background:var(--crit-dim);color:var(--critical)">${c.cvss_score}</span>`:''}
      ${c.in_kev?'<span class="badge badge-critical">KEV</span>':''}
    </div>
  </div>`).join(''):`<div class="text-sm text-3">No CVEs this period</div>`;

  const actorsHtml=d.topActors?.length?`
    <div class="sector-actor-grid">
      ${d.topActors.map(a=>`<div class="actor-card">
        <div class="actor-name">${esc(a.name)}</div>
        <div class="actor-meta">${a.origin_country?`${esc(a.origin_country)} · `:''}${esc(a.motivation||'unknown')} · ${a.cnt} threat${a.cnt!==1?'s':''}</div>
      </div>`).join('')}
    </div>`:'';

  const rows=d.threats?.length?`<table class="data-table"><thead><tr>
    <th>Severity</th><th>Threat</th><th>Type</th><th>Confidence</th><th>IOCs</th><th>Age</th>
  </tr></thead><tbody>${d.threats.map(t=>`<tr>
    <td>${sevBadge(t.severity)}</td>
    <td class="cell-title"><a href="/threat-detail.html?id=${t.id}">${esc(t.title)}</a><div class="cell-sub">${esc(t.source_name||'')}</div></td>
    <td><span class="text-xs text-2">${typeLabel(t.threat_type)}</span></td>
    <td>${credBar(t.credibility_score)}</td>
    <td>${t.ioc_count>0?`<span class="badge badge-ioc">${t.ioc_count}</span>`:'—'}</td>
    <td class="text-xs text-3">${relTime(t.ingested_at)}</td>
  </tr>`).join('')}</tbody></table>`:`<div class="empty"><div class="empty-icon">${icons[s]}</div><div class="empty-title">No ${s} threats in the last 7 days</div></div>`;

  const actorsSection = actorsHtml ? `
    <div class="card">
      <div class="card-head"><div class="card-title">Threat Actors</div></div>
      ${actorsHtml}
    </div>` : '';

  document.getElementById('sector-content').innerHTML=`
    <div class="sector-layout">
      <div class="card sector-main">
        <div class="card-head"><div class="card-title">${icons[s]} ${s.charAt(0).toUpperCase()+s.slice(1)} Threats (${d.threats?.length||0})</div></div>
        <div class="table-wrap">${rows}</div>
      </div>
      <aside class="sector-side">
        <div class="card">
          <div class="card-head"><div class="card-title">Top CVEs</div></div>
          <div class="sector-cve-list">${cvesHtml}</div>
        </div>
        ${actorsSection}
      </aside>
    </div>`;
}

loadSector('banking');
