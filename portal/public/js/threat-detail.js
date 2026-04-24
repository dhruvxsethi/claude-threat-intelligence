// Threat Detail page

const id = new URLSearchParams(location.search).get('id');

async function loadThreat() {
  if (!id) {
    document.getElementById('detail-content').innerHTML = `
      <div class="empty-state"><div class="empty-title">No threat ID provided</div></div>`;
    return;
  }

  const res = await fetch(`/api/threats/${id}`);
  if (!res.ok) {
    document.getElementById('detail-content').innerHTML = `
      <div class="empty-state"><div class="empty-title">Threat not found</div></div>`;
    return;
  }

  const t = await res.json();
  document.getElementById('breadcrumb-title').textContent = t.title?.slice(0, 50) + '...';
  document.title = `${t.title} — CTI`;

  const sectorImpact = t.sector_impact || {};
  const impactHtml = Object.entries(sectorImpact).map(([s, v]) => `
    <div style="padding:10px;background:var(--surface-2);border-radius:var(--radius);border:1px solid var(--border)">
      <div class="flex items-center justify-between mb-2">
        <span>${s === 'banking' ? '🏦' : s === 'government' ? '🏛️' : '🏥'} ${s}</span>
        <span style="font-weight:700;color:${v.score >= 70 ? 'var(--critical)' : v.score >= 40 ? 'var(--medium)' : 'var(--text-muted)'}">${v.score}/100</span>
      </div>
      <div class="text-xs text-muted">${v.reason || ''}</div>
      <div style="height:3px;background:var(--surface-3);border-radius:2px;margin-top:8px">
        <div style="height:3px;width:${v.score}%;background:${v.score >= 70 ? 'var(--critical)' : v.score >= 40 ? 'var(--medium)' : 'var(--low)'};border-radius:2px"></div>
      </div>
    </div>
  `).join('');

  const cvesHtml = t.cves?.length ? t.cves.map(c => `
    <div class="cve-card">
      <div class="cve-header">
        <span class="cve-id">${c.cve_id}</span>
        ${c.cvss_score ? `<span class="cvss-score" style="background:${c.cvss_score >= 9 ? 'var(--critical-bg)' : c.cvss_score >= 7 ? 'var(--high-bg)' : 'var(--medium-bg)'};color:${c.cvss_score >= 9 ? 'var(--critical)' : c.cvss_score >= 7 ? 'var(--high)' : 'var(--medium)'}">CVSS ${c.cvss_score}</span>` : ''}
        ${c.in_kev ? '<span class="badge badge-critical">CISA KEV</span>' : ''}
        ${c.patch_available ? '<span class="badge badge-low">Patch Available</span>' : '<span class="badge badge-critical">No Patch</span>'}
      </div>
      <div class="cve-desc">${c.description || ''}</div>
      ${c.cvss_vector ? `<div class="text-xs font-mono text-muted mt-2">${c.cvss_vector}</div>` : ''}
      ${(c.affected_products || []).length ? `<div class="text-xs text-muted mt-2">Affects: ${c.affected_products.slice(0,3).join(', ')}</div>` : ''}
    </div>
  `).join('') : '<div class="text-muted text-sm">No CVEs identified</div>';

  const iocsHtml = t.iocs?.length ? t.iocs.map(i => `
    <div class="ioc-item">
      ${iocTypeBadge(i.ioc_type)}
      <span class="ioc-value" title="${i.ioc_value}">${i.ioc_value}</span>
      ${i.malware_family ? `<span class="text-xs" style="color:var(--medium)">${i.malware_family}</span>` : ''}
      <span class="ioc-confidence">${i.confidence}%</span>
      <button class="copy-btn" onclick="copyToClipboard('${i.ioc_value.replace(/'/g,'\\\'')}')" title="Copy">⎘</button>
    </div>
  `).join('') : '<div class="text-muted text-sm">No IOCs extracted</div>';

  const ttpsHtml = t.ttps?.length ? t.ttps.map(p => `
    <div class="ttp-item">
      <div class="flex items-center gap-2">
        <span class="ttp-id">${p.mitre_id}</span>
        <span class="text-xs text-muted">${p.tactic || ''}</span>
      </div>
      <div class="ttp-name">${p.technique || ''}</div>
      ${p.procedure ? `<div class="ttp-proc">${p.procedure}</div>` : ''}
    </div>
  `).join('') : '<div class="text-muted text-sm">No TTPs mapped</div>';

  const actorsHtml = t.actors?.length ? t.actors.map(a => `
    <div class="actor-card">
      <div class="actor-name">${a.name}</div>
      <div class="actor-meta">
        ${a.origin_country ? `🌍 ${a.origin_country} · ` : ''}
        ${a.motivation !== 'unknown' ? a.motivation : ''}
        ${a.sophistication !== 'unknown' ? ` · ${a.sophistication}` : ''}
      </div>
      ${a.aliases?.length ? `<div class="text-xs text-muted mt-1">Also known as: ${a.aliases.join(', ')}</div>` : ''}
      ${a.description ? `<div class="text-xs text-dim mt-2">${a.description}</div>` : ''}
    </div>
  `).join('') : '<div class="text-muted text-sm">No threat actors identified</div>';

  const relatedHtml = t.related?.length ? t.related.map(r => `
    <a href="/threat-detail.html?id=${r.id}" style="display:block;padding:8px 12px;background:var(--surface-2);border-radius:var(--radius);margin-bottom:6px;color:var(--text);font-size:0.82rem">
      <div>${severityBadge(r.severity)} ${r.title?.slice(0, 60)}</div>
      <div class="text-xs text-muted mt-1">${relativeTime(r.ingested_at)}</div>
    </a>
  `).join('') : '<div class="text-muted text-sm">No correlated threats</div>';

  const geoHtml = (t.geography || []).length
    ? t.geography.map(g => `<span class="badge badge-unknown">${g}</span>`).join(' ')
    : '<span class="text-muted text-sm">Unknown</span>';

  const malwareHtml = (t.malware_families || []).length
    ? t.malware_families.map(m => `
        <div style="padding:8px 10px;background:var(--surface-2);border-radius:var(--radius);margin-bottom:6px">
          <div style="font-weight:600;color:var(--text)">${m.name}</div>
          <div class="text-xs text-muted">${m.type} ${m.aliases?.length ? `· ${m.aliases.join(', ')}` : ''}</div>
        </div>
      `).join('')
    : '<div class="text-muted text-sm">None identified</div>';

  document.getElementById('detail-content').innerHTML = `
    <div class="detail-header">
      <div class="detail-title">${t.title}</div>
      <div class="detail-meta">
        ${severityBadge(t.severity)}
        <span class="badge badge-unknown">${threatTypeLabel(t.threat_type)}</span>
        ${(t.sectors || []).map(sectorBadge).join(' ')}
        ${t.is_corroborated ? '<span class="badge badge-low">✓ Corroborated</span>' : ''}
        <span class="text-xs text-muted">Credibility: ${t.credibility_score}/100</span>
        <a href="${t.source_url}" target="_blank" class="text-xs" style="color:var(--primary)">↗ Source: ${t.source_name}</a>
      </div>
    </div>

    <div class="detail-summary">${t.summary}</div>

    <div class="detail-grid">
      <!-- Left column -->
      <div>

        <!-- Sector Impact -->
        <div class="mb-4">
          <div class="section-title">Sector Impact</div>
          <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px">${impactHtml}</div>
        </div>

        <!-- CVEs -->
        <div class="mb-4">
          <div class="section-title">CVEs (${t.cves?.length || 0})</div>
          ${cvesHtml}
        </div>

        <!-- IOCs -->
        <div class="mb-4">
          <div class="section-title">
            IOCs (${t.iocs?.length || 0})
            ${t.iocs?.length ? `<button class="btn btn-ghost" style="float:right;padding:2px 8px;font-size:0.72rem" onclick="exportDetailIocs('${id}')">↓ Export</button>` : ''}
          </div>
          <div style="max-height:300px;overflow-y:auto">${iocsHtml}</div>
        </div>

        <!-- TTPs -->
        <div class="mb-4">
          <div class="section-title">MITRE ATT&CK TTPs (${t.ttps?.length || 0})</div>
          ${ttpsHtml}
        </div>

        <!-- Threat Actors -->
        <div class="mb-4">
          <div class="section-title">Threat Actors (${t.actors?.length || 0})</div>
          ${actorsHtml}
        </div>

        <!-- Malware Families -->
        <div class="mb-4">
          <div class="section-title">Malware Families</div>
          ${malwareHtml}
        </div>

      </div>

      <!-- Right sidebar -->
      <div>
        <div class="card mb-3">
          <div class="section-title">Metadata</div>
          <div style="font-size:0.8rem">
            <div class="flex justify-between" style="padding:6px 0;border-bottom:1px solid var(--border)">
              <span class="text-muted">Published</span>
              <span>${fmtDate(t.published_at)}</span>
            </div>
            <div class="flex justify-between" style="padding:6px 0;border-bottom:1px solid var(--border)">
              <span class="text-muted">Ingested</span>
              <span>${fmtDate(t.ingested_at)}</span>
            </div>
            <div class="flex justify-between" style="padding:6px 0;border-bottom:1px solid var(--border)">
              <span class="text-muted">Source Tier</span>
              <span>Tier ${t.source_tier || '?'}</span>
            </div>
            <div class="flex justify-between" style="padding:6px 0;border-bottom:1px solid var(--border)">
              <span class="text-muted">Kill Chain</span>
              <span>${t.kill_chain_stage || '—'}</span>
            </div>
            <div class="flex justify-between" style="padding:6px 0;border-bottom:1px solid var(--border)">
              <span class="text-muted">Geography</span>
              <span>${(t.geography || []).join(', ') || '—'}</span>
            </div>
            <div class="flex justify-between" style="padding:6px 0">
              <span class="text-muted">Corroborations</span>
              <span>${t.corroboration_count || 0}</span>
            </div>
          </div>
        </div>

        <div class="card mb-3">
          <div class="section-title">Related Threats (${t.related?.length || 0})</div>
          ${relatedHtml}
        </div>

        ${(t.affected_products || []).length ? `
          <div class="card mb-3">
            <div class="section-title">Affected Products</div>
            ${t.affected_products.map(p => `
              <div style="padding:6px;background:var(--surface-2);border-radius:4px;margin-bottom:4px;font-size:0.78rem">
                <span style="color:var(--text)">${p.vendor} ${p.product}</span>
                ${p.version_range ? `<div class="text-xs text-muted">${p.version_range}</div>` : ''}
              </div>
            `).join('')}
          </div>
        ` : ''}

      </div>
    </div>
  `;
}

function exportDetailIocs(threatId) {
  fetch(`/api/iocs?days=365`).then(r => r.json()).then(data => {
    const iocs = data.iocs?.filter(i => i.threat_id === threatId) || [];
    const csv = 'type,value,confidence,malware_family,context\n' +
      iocs.map(i => `${i.ioc_type},${i.ioc_value},${i.confidence},${i.malware_family || ''},${i.context || ''}`).join('\n');
    download(csv, `iocs-${threatId.slice(0,8)}.csv`, 'text/csv');
  });
}

function download(content, filename, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], { type }));
  a.download = filename;
  a.click();
}

loadThreat();
