const _id = new URLSearchParams(location.search).get('id');
let _data = null;
let _activeTab = 'overview';

const SECTOR_LABELS = { banking: 'Banking', government: 'Government', healthcare: 'Healthcare' };

async function load() {
  if (!_id) return show404();
  const r = await fetch(`/api/threats/${_id}`);
  if (!r.ok) return show404();
  _data = await r.json();
  const t = _data;

  const bcEl = document.getElementById('bc-title');
  if (bcEl) bcEl.textContent = t.title?.slice(0, 60) + '…';
  document.title = `${t.title} — Radar`;

  const si = t.sector_impact || {};

  document.getElementById('detail-root').innerHTML = `
    <!-- Header -->
    <div class="d-header">
      <div class="d-header-top">
        ${sevBadge(t.severity)}
        <span class="badge badge-unknown">${typeLabel(t.threat_type)}</span>
        ${(t.sectors || []).map(secBadge).join(' ')}
        ${t.is_corroborated ? '<span class="badge badge-low">Corroborated</span>' : ''}
      </div>
      <h1 class="d-title">${esc(t.title)}</h1>
      <p class="d-summary">${esc(t.summary || 'No summary available.')}</p>
      <div class="d-source-row">
        <span class="text-xs text-3">Source: <a href="${t.source_url}" target="_blank" style="color:var(--blue)">${esc(t.source_name || '—')}</a></span>
        <span class="d-dot"></span>
        <span class="text-xs text-3">Credibility ${t.credibility_score}/100</span>
        <span class="d-dot"></span>
        <span class="text-xs text-3">${relTime(t.ingested_at)}</span>
      </div>
    </div>

    <!-- Stat bar -->
    <div class="d-statbar">
      <div class="d-stat" onclick="switchTab('iocs')">
        <div class="d-stat-val">${t.iocs?.length || 0}</div>
        <div class="d-stat-label">IOCs</div>
      </div>
      <div class="d-stat" onclick="switchTab('cves')">
        <div class="d-stat-val">${t.cves?.length || 0}</div>
        <div class="d-stat-label">CVEs</div>
      </div>
      <div class="d-stat" onclick="switchTab('ttps')">
        <div class="d-stat-val">${t.ttps?.length || 0}</div>
        <div class="d-stat-label">TTPs</div>
      </div>
      <div class="d-stat" onclick="switchTab('actors')">
        <div class="d-stat-val">${t.actors?.length || 0}</div>
        <div class="d-stat-label">Actors</div>
      </div>
    </div>

    <!-- Layout -->
    <div class="d-layout">
      <!-- Tab pane (left) -->
      <div class="d-main">
        <div class="d-tabs">
          <button class="d-tab active" data-tab="overview" onclick="switchTab('overview')">Overview</button>
          <button class="d-tab" data-tab="iocs" onclick="switchTab('iocs')">IOCs${t.iocs?.length ? ` <span class="d-tab-count">${t.iocs.length}</span>` : ''}</button>
          <button class="d-tab" data-tab="cves" onclick="switchTab('cves')">CVEs${t.cves?.length ? ` <span class="d-tab-count">${t.cves.length}</span>` : ''}</button>
          <button class="d-tab" data-tab="ttps" onclick="switchTab('ttps')">MITRE ATT&CK${t.ttps?.length ? ` <span class="d-tab-count">${t.ttps.length}</span>` : ''}</button>
          <button class="d-tab" data-tab="actors" onclick="switchTab('actors')">Actors${t.actors?.length ? ` <span class="d-tab-count">${t.actors.length}</span>` : ''}</button>
        </div>
        <div id="tab-content" class="d-tabcontent"></div>
      </div>

      <!-- Sidebar (right) -->
      <div class="d-sidebar">
        <div class="card mb-3">
          <div class="card-head"><div class="card-title">Metadata</div></div>
          <div style="padding:4px 0">
            ${[
              ['Kill Chain',     t.kill_chain_stage || '—'],
              ['Geography',      (t.geography || []).join(', ') || '—'],
              ['Published',      fmtDate(t.published_at)],
              ['Ingested',       fmtDate(t.ingested_at)],
              ['Source Tier',    `Tier ${t.source_tier || '?'}`],
              ['Corroborations', t.corroboration_count || 0],
            ].map(([k, v]) => `<div class="meta-row"><span class="meta-key">${k}</span><span class="meta-val">${v}</span></div>`).join('')}
          </div>
        </div>

        ${(t.related?.length) ? `<div class="card">
          <div class="card-head"><div class="card-title">Related (${t.related.length})</div></div>
          <div style="padding:8px">
            ${t.related.map(r => `<a href="/threat-detail.html?id=${r.id}" class="d-related-item">
              <div class="d-related-sev">${sevBadge(r.severity)}</div>
              <div class="d-related-title">${esc(r.title?.slice(0, 55))}</div>
              <div class="text-xs text-3">${relTime(r.ingested_at)}</div>
            </a>`).join('')}
          </div>
        </div>` : ''}
      </div>
    </div>`;

  renderTab('overview');
}

function switchTab(name) {
  _activeTab = name;
  document.querySelectorAll('.d-tab').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  renderTab(name);
}

function renderTab(name) {
  const t = _data;
  const el = document.getElementById('tab-content');
  if (!el || !t) return;

  if (name === 'overview') {
    const si = t.sector_impact || {};
    const sImpact = ['banking', 'government', 'healthcare'].map(s => {
      const v = si[s] || { score: 0, reason: 'Not relevant' };
      const c = v.score >= 70 ? 'var(--critical)' : v.score >= 40 ? 'var(--medium)' : 'var(--low)';
      return `<div class="impact-box">
        <div class="impact-sector">${SECTOR_LABELS[s]}</div>
        <div class="impact-score" style="color:${c}">${v.score}<span style="font-size:.9rem;color:var(--text-3)">/100</span></div>
        <div class="impact-bar" style="margin-top:8px"><div class="impact-fill" style="width:${v.score}%;background:${c}"></div></div>
        <div class="impact-reason">${esc(v.reason || '')}</div>
      </div>`;
    }).join('');

    const products = (t.affected_products || []).map(p =>
      `<div class="d-product">${esc(p.vendor)} ${esc(p.product)}${p.version_range ? `<span class="text-xs text-3"> ${esc(p.version_range)}</span>` : ''}</div>`
    ).join('');

    const malware = (t.malware_families || []).map(m =>
      `<span class="badge badge-unknown" style="margin:2px">${esc(m.name)} <span class="text-3" style="font-weight:400">${m.type}</span></span>`
    ).join('');

    el.innerHTML = `
      <div class="d-block">
        <div class="d-block-title">Sector Impact</div>
        <div class="impact-grid">${sImpact}</div>
      </div>
      ${products ? `<div class="d-block">
        <div class="d-block-title">Affected Products</div>
        <div class="d-products">${products}</div>
      </div>` : ''}
      ${malware ? `<div class="d-block">
        <div class="d-block-title">Malware Families</div>
        <div style="margin-top:8px">${malware}</div>
      </div>` : ''}`;

  } else if (name === 'iocs') {
    const rows = t.iocs?.length
      ? t.iocs.map(i => `<div class="ioc-row">
          ${iocPill(i.ioc_type)}
          <span class="ioc-val" title="${esc(i.ioc_value)}">${esc(i.ioc_value)}</span>
          ${i.malware_family ? `<span class="text-xs" style="color:var(--medium)">${esc(i.malware_family)}</span>` : ''}
          <span class="ioc-conf">${i.confidence}%</span>
          <button class="copy-btn" onclick="copyToClipboard('${i.ioc_value.replace(/'/g, "\\'")}')">⎘</button>
        </div>`).join('')
      : '<div class="d-empty">No IOCs extracted</div>';

    el.innerHTML = `<div class="d-block">
      <div class="d-block-title" style="display:flex;align-items:center;justify-content:space-between">
        <span>Indicators of Compromise</span>
        ${t.iocs?.length ? `<button class="btn btn-ghost" style="padding:2px 10px;font-size:.65rem" onclick="exportIocs()">Export CSV</button>` : ''}
      </div>
      ${rows}
    </div>`;

  } else if (name === 'cves') {
    const rows = t.cves?.length
      ? t.cves.map(c => {
          const sc = c.cvss_score;
          const col = sc >= 9 ? 'var(--critical)' : sc >= 7 ? 'var(--high)' : sc >= 4 ? 'var(--medium)' : 'var(--low)';
          return `<div class="cve-card">
            <div class="flex items-center gap-2" style="flex-wrap:wrap">
              <span class="cve-id">${c.cve_id}</span>
              ${sc ? `<span class="cvss-chip" style="background:${col}22;color:${col}">CVSS ${sc}</span>` : ''}
              ${c.in_kev          ? '<span class="badge badge-critical">CISA KEV</span>'    : ''}
              ${c.patch_available ? '<span class="badge badge-low">Patch Available</span>' : '<span class="badge badge-critical">No Patch</span>'}
              ${c.exploited_in_wild ? '<span class="badge badge-critical">Exploited ITW</span>' : ''}
            </div>
            <div class="cve-desc">${esc(c.description || '')}</div>
            ${c.cvss_vector ? `<div class="text-xs mono text-3 mt-2">${c.cvss_vector}</div>` : ''}
          </div>`;
        }).join('')
      : '<div class="d-empty">No CVEs identified</div>';

    el.innerHTML = `<div class="d-block"><div class="d-block-title">Vulnerabilities</div>${rows}</div>`;

  } else if (name === 'ttps') {
    const rows = t.ttps?.length
      ? t.ttps.map(p => `<div class="ttp-item">
          <div style="display:flex;align-items:center;gap:8px">
            <span class="ttp-id">${p.mitre_id}</span>
            <span class="text-xs text-3">${p.tactic || ''}</span>
          </div>
          <div class="ttp-name">${esc(p.technique || '')}</div>
          ${p.procedure ? `<div class="ttp-proc">${esc(p.procedure)}</div>` : ''}
        </div>`).join('')
      : '<div class="d-empty">No TTPs mapped</div>';

    el.innerHTML = `<div class="d-block"><div class="d-block-title">MITRE ATT&CK Techniques</div>${rows}</div>`;

  } else if (name === 'actors') {
    const rows = t.actors?.length
      ? t.actors.map(a => `<div class="actor-card">
          <div class="actor-name">${esc(a.name)}</div>
          <div class="actor-meta">${[
            a.origin_country,
            a.motivation !== 'unknown' ? a.motivation : null,
            a.sophistication !== 'unknown' ? a.sophistication : null,
          ].filter(Boolean).join(' · ') || '—'}</div>
          ${a.aliases?.length ? `<div class="text-xs text-3 mt-2">Also known as: ${a.aliases.join(', ')}</div>` : ''}
          ${a.description ? `<div class="text-xs text-2 mt-2">${esc(a.description)}</div>` : ''}
        </div>`).join('')
      : '<div class="d-empty">No actors identified</div>';

    el.innerHTML = `<div class="d-block"><div class="d-block-title">Threat Actors</div>${rows}</div>`;
  }
}

function exportIocs() {
  fetch(`/api/iocs?days=365`).then(r => r.json()).then(d => {
    const rows = (d.iocs || []).filter(i => i.threat_id === _id);
    const csv = 'type,value,confidence,malware_family,context\n' +
      rows.map(i => `${i.ioc_type},"${i.ioc_value}",${i.confidence},"${i.malware_family || ''}","${i.context || ''}"`).join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = `iocs-${_id?.slice(0, 8)}.csv`;
    a.click();
  });
}

function show404() {
  document.getElementById('detail-root').innerHTML =
    `<div class="empty"><div class="empty-title">Threat not found</div></div>`;
}

load();
