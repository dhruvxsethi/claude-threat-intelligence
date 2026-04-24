const _id = new URLSearchParams(location.search).get('id');

async function load() {
  if (!_id) return show404();
  const r = await fetch(`/api/threats/${_id}`);
  if (!r.ok) return show404();
  const t = await r.json();

  const bcEl = document.getElementById('bc-title');
  if (bcEl) bcEl.textContent = t.title?.slice(0,60)+'…';
  document.title = `${t.title} — CTI`;

  const si = t.sector_impact||{};
  const sImpact = ['banking','government','healthcare'].map(s=>{
    const v=si[s]||{score:0,reason:'Not relevant'};
    const c = v.score>=70?'var(--critical)':v.score>=40?'var(--medium)':'var(--low)';
    const icons={banking:'🏦',government:'🏛️',healthcare:'🏥'};
    return `<div class="impact-box">
      <div class="impact-sector">${icons[s]} ${s}</div>
      <div class="impact-score" style="color:${c}">${v.score}<span style="font-size:1rem;color:var(--text-3)">/100</span></div>
      <div class="impact-reason">${esc(v.reason||'')}</div>
      <div class="impact-bar"><div class="impact-fill" style="width:${v.score}%;background:${c}"></div></div>
    </div>`;
  }).join('');

  const cvesHtml = t.cves?.length ? t.cves.map(c=>{
    const sc=c.cvss_score;
    const scColor=sc>=9?'var(--critical)':sc>=7?'var(--high)':sc>=4?'var(--medium)':'var(--low)';
    return `<div class="cve-card">
      <div class="flex items-center gap-2">
        <span class="cve-id">${c.cve_id}</span>
        ${sc?`<span class="cvss-chip" style="background:${scColor}22;color:${scColor}">CVSS ${sc}</span>`:''}
        ${c.in_kev?'<span class="badge badge-critical">CISA KEV</span>':''}
        ${c.patch_available?'<span class="badge badge-low">Patch Available</span>':'<span class="badge badge-critical">No Patch</span>'}
        ${c.exploited_in_wild?'<span class="badge badge-critical">Exploited ITW</span>':''}
      </div>
      <div class="cve-desc">${esc(c.description||'')}</div>
      ${c.cvss_vector?`<div class="text-xs mono text-3 mt-2">${c.cvss_vector}</div>`:''}
    </div>`;
  }).join('') : '<div class="text-sm text-3">No CVEs identified</div>';

  const iocsHtml = t.iocs?.length ? t.iocs.map(i=>`<div class="ioc-row">
    ${iocPill(i.ioc_type)}
    <span class="ioc-val" title="${esc(i.ioc_value)}">${esc(i.ioc_value)}</span>
    ${i.malware_family?`<span class="text-xs" style="color:var(--medium);white-space:nowrap">${esc(i.malware_family)}</span>`:''}
    <span class="ioc-conf">${i.confidence}%</span>
    <button class="copy-btn" onclick="copyToClipboard('${i.ioc_value.replace(/'/g,"\\'")}')">⎘</button>
  </div>`).join('') : '<div class="text-sm text-3">No IOCs extracted</div>';

  const ttpsHtml = t.ttps?.length ? t.ttps.map(p=>`<div class="ttp-item">
    <div class="flex items-center gap-2"><span class="ttp-id">${p.mitre_id}</span><span class="text-xs text-3">${p.tactic||''}</span></div>
    <div class="ttp-name">${esc(p.technique||'')}</div>
    ${p.procedure?`<div class="ttp-proc">${esc(p.procedure)}</div>`:''}
  </div>`).join('') : '<div class="text-sm text-3">No TTPs mapped</div>';

  const actorsHtml = t.actors?.length ? t.actors.map(a=>`<div class="actor-card">
    <div class="actor-name">${esc(a.name)}</div>
    <div class="actor-meta">${a.origin_country?`🌍 ${a.origin_country} · `:''}${a.motivation!=='unknown'?a.motivation:''}${a.sophistication!=='unknown'?` · ${a.sophistication}`:''}</div>
    ${a.aliases?.length?`<div class="text-xs text-3 mt-2">Also: ${a.aliases.join(', ')}</div>`:''}
    ${a.description?`<div class="text-xs text-2 mt-2">${esc(a.description)}</div>`:''}
  </div>`).join('') : '<div class="text-sm text-3">No actors identified</div>';

  const relatedHtml = t.related?.length ? t.related.map(r=>`<a href="/threat-detail.html?id=${r.id}" style="display:block;padding:9px 12px;background:var(--surface-2);border-radius:8px;margin-bottom:6px;border:1px solid var(--border)">
    <div style="font-size:.84rem;font-weight:500;color:var(--text)">${sevBadge(r.severity)} ${esc(r.title?.slice(0,60))}</div>
    <div class="text-xs text-3 mt-1">${relTime(r.ingested_at)}</div>
  </a>`).join('') : '<div class="text-sm text-3">No correlated threats</div>';

  const affectedHtml = (t.affected_products||[]).length ? t.affected_products.map(p=>`<div style="padding:6px 10px;background:var(--surface-2);border-radius:6px;margin-bottom:4px;font-size:.8rem">
    <span style="color:var(--text)">${esc(p.vendor)} ${esc(p.product)}</span>
    ${p.version_range?`<div class="text-xs text-3">${esc(p.version_range)}</div>`:''}
  </div>`).join('') : '';

  document.getElementById('detail-root').innerHTML = `
    <div class="detail-title">${esc(t.title)}</div>
    <div class="detail-meta">
      ${sevBadge(t.severity)}
      <span class="badge badge-unknown">${typeLabel(t.threat_type)}</span>
      ${(t.sectors||[]).map(secBadge).join(' ')}
      ${t.is_corroborated?'<span class="badge badge-low">✓ Corroborated</span>':''}
      <span class="text-xs text-3">Credibility: ${t.credibility_score}/100</span>
      <a href="${t.source_url}" target="_blank" class="text-xs" style="color:var(--blue)">↗ ${esc(t.source_name)}</a>
    </div>
    <div class="detail-summary">${esc(t.summary||'No summary available.')}</div>

    <div class="detail-grid">
      <div>
        <div class="mb-4">
          <div class="block-title">Sector Impact</div>
          <div class="impact-grid">${sImpact}</div>
        </div>
        <div class="mb-4">
          <div class="block-title">CVEs (${t.cves?.length||0}) <span class="text-3 text-xs" style="text-transform:none;letter-spacing:0;font-weight:400">Common Vulnerabilities & Exposures</span></div>
          ${cvesHtml}
        </div>
        <div class="mb-4">
          <div class="block-title">
            IOCs (${t.iocs?.length||0})
            ${t.iocs?.length?`<button class="btn btn-ghost" style="padding:2px 10px;font-size:.7rem" onclick="exportIocs()">↓ Export</button>`:''}
          </div>
          <div style="max-height:320px;overflow-y:auto">${iocsHtml}</div>
        </div>
        <div class="mb-4">
          <div class="block-title">MITRE ATT&CK TTPs (${t.ttps?.length||0})</div>
          ${ttpsHtml}
        </div>
        <div class="mb-4">
          <div class="block-title">Threat Actors (${t.actors?.length||0})</div>
          ${actorsHtml}
        </div>
        ${(t.malware_families||[]).length?`<div class="mb-4"><div class="block-title">Malware Families</div>
          ${t.malware_families.map(m=>`<div style="padding:8px 12px;background:var(--surface-2);border-radius:8px;margin-bottom:6px;font-size:.84rem">
            <span style="font-weight:600;color:var(--text)">${esc(m.name)}</span>
            <span class="text-xs text-3"> · ${m.type}${m.aliases?.length?' · '+m.aliases.join(', '):''}</span>
          </div>`).join('')}</div>`:''}
      </div>

      <div>
        <div class="card mb-3">
          <div class="block-title">Metadata</div>
          ${[
            ['Published', fmtDate(t.published_at)],
            ['Ingested', fmtDate(t.ingested_at)],
            ['Source Tier', `Tier ${t.source_tier||'?'}`],
            ['Kill Chain', t.kill_chain_stage||'—'],
            ['Geography', (t.geography||[]).join(', ')||'—'],
            ['Corroborations', t.corroboration_count||0],
            ['Slot', t.slot||'—'],
          ].map(([k,v])=>`<div class="meta-row"><span class="meta-key">${k}</span><span class="meta-val">${v}</span></div>`).join('')}
        </div>
        <div class="card mb-3">
          <div class="block-title">Related Threats (${t.related?.length||0})</div>
          ${relatedHtml}
        </div>
        ${affectedHtml?`<div class="card"><div class="block-title">Affected Products</div>${affectedHtml}</div>`:''}
      </div>
    </div>`;
}

function exportIocs() {
  fetch(`/api/iocs?days=365`).then(r=>r.json()).then(d=>{
    const rows = (d.iocs||[]).filter(i=>i.threat_id===_id);
    const csv = 'type,value,confidence,malware_family,context\n'+rows.map(i=>`${i.ioc_type},"${i.ioc_value}",${i.confidence},"${i.malware_family||''}","${i.context||''}"`).join('\n');
    const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'})); a.download=`iocs-${_id?.slice(0,8)}.csv`; a.click();
  });
}

function show404() {
  document.getElementById('detail-root').innerHTML=`<div class="empty"><div class="empty-icon">🔍</div><div class="empty-title">Threat not found</div></div>`;
}

load();
