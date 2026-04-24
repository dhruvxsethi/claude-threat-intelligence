// Sectors page

let currentSector = 'banking';

async function switchSector(sector, btn) {
  currentSector = sector;
  document.querySelectorAll('.sector-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  await loadSector(sector);
}

async function loadSector(sector) {
  document.getElementById('sector-content').innerHTML = `
    <div class="empty-state"><div class="empty-icon">⏳</div><div class="empty-title">Loading ${sector} data...</div></div>`;

  const res = await fetch(`/api/sectors/${sector}?days=7`);
  const data = await res.json();

  const icons = { banking: '🏦', government: '🏛️', healthcare: '🏥' };
  const colors = { banking: 'var(--banking)', government: 'var(--government)', healthcare: 'var(--healthcare)' };

  const topCvesHtml = data.topCves?.length ? data.topCves.map(c => `
    <div class="cve-card">
      <div class="cve-header">
        <a class="cve-id" href="/threat-detail.html?id=${c.threat_id}">${c.cve_id}</a>
        ${c.cvss_score ? `<span class="cvss-score" style="background:var(--critical-bg);color:var(--critical);font-size:0.8rem;padding:2px 8px;border-radius:4px">${c.cvss_score}</span>` : ''}
        ${c.in_kev ? '<span class="badge badge-critical">CISA KEV</span>' : ''}
      </div>
    </div>
  `).join('') : '<div class="text-muted text-sm">No CVEs in this period</div>';

  const actorsHtml = data.topActors?.length ? data.topActors.map(a => `
    <div class="actor-card">
      <div class="actor-name">${a.name}</div>
      <div class="actor-meta">
        ${a.origin_country ? `🌍 ${a.origin_country} · ` : ''}
        ${a.motivation || ''} · ${a.cnt} threat${a.cnt !== 1 ? 's' : ''}
      </div>
    </div>
  `).join('') : '<div class="text-muted text-sm">No attributed actors</div>';

  const threatsHtml = data.threats?.length ? `
    <table class="threat-table">
      <thead>
        <tr>
          <th>Severity</th>
          <th>Threat</th>
          <th>Type</th>
          <th>Confidence</th>
          <th>IOCs</th>
          <th>Age</th>
        </tr>
      </thead>
      <tbody>
        ${data.threats.map(t => `
          <tr>
            <td>${severityBadge(t.severity)}</td>
            <td>
              <a class="threat-title-link" href="/threat-detail.html?id=${t.id}">${t.title}</a>
              <div class="threat-meta">${t.source_name || ''}</div>
            </td>
            <td><span class="text-xs text-dim">${threatTypeLabel(t.threat_type)}</span></td>
            <td><div class="flex gap-2 items-center">${credBar(t.credibility_score)}</div></td>
            <td>${t.ioc_count > 0 ? `<span class="badge badge-ioc">${t.ioc_count}</span>` : '—'}</td>
            <td class="text-xs text-muted">${relativeTime(t.ingested_at)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  ` : `
    <div class="empty-state">
      <div class="empty-icon">${icons[sector]}</div>
      <div class="empty-title">No ${sector} threats in the last 7 days</div>
    </div>
  `;

  document.getElementById('sector-content').innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px">
      <div class="card">
        <div class="card-header"><div class="card-title">🔴 Top CVEs</div></div>
        ${topCvesHtml}
      </div>
      <div class="card">
        <div class="card-header"><div class="card-title">👤 Threat Actors</div></div>
        ${actorsHtml}
      </div>
    </div>
    <div class="card">
      <div class="card-header">
        <div class="card-title">${icons[sector]} ${sector.charAt(0).toUpperCase()+sector.slice(1)} Threats (${data.threats?.length || 0})</div>
      </div>
      <div class="threat-table-wrap">${threatsHtml}</div>
    </div>
  `;
}

// Init
loadSector('banking');
