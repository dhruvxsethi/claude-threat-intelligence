// IOC Explorer page

async function loadIocs() {
  const type = document.getElementById('f-ioc-type')?.value || '';
  const days = document.getElementById('f-ioc-days')?.value || '7';
  const confidence = document.getElementById('f-ioc-confidence')?.value || '50';
  const search = document.getElementById('f-ioc-search')?.value || '';

  const params = new URLSearchParams({ days, min_confidence: confidence, limit: 200 });
  if (type) params.set('type', type);
  if (search) params.set('search', search);

  const res = await fetch(`/api/iocs?${params}`);
  const data = await res.json();

  renderIocTypeChips(data.type_counts || []);
  renderIocs(data.iocs || []);
}

function renderIocTypeChips(typeCounts) {
  const el = document.getElementById('ioc-type-chips');
  if (!el) return;
  el.innerHTML = typeCounts.map(t => `
    <span style="padding:3px 10px;border-radius:20px;font-size:0.72rem;cursor:pointer;background:${IOC_COLORS[t.ioc_type] || '#6b7280'}22;color:${IOC_COLORS[t.ioc_type] || '#6b7280'};border:1px solid ${IOC_COLORS[t.ioc_type] || '#6b7280'}44"
      onclick="document.getElementById('f-ioc-type').value='${t.ioc_type}';loadIocs()">
      ${t.ioc_type.replace('_',' ')} (${t.cnt})
    </span>
  `).join('');
}

function renderIocs(iocs) {
  const el = document.getElementById('iocs-list');
  const countEl = document.getElementById('ioc-count');
  if (countEl) countEl.textContent = `${iocs.length} IOCs`;

  if (!iocs.length) {
    el.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🔍</div>
        <div class="empty-title">No IOCs found</div>
        <div class="empty-sub">Adjust filters or run the pipeline.</div>
      </div>`;
    return;
  }

  el.innerHTML = iocs.map(i => `
    <div class="ioc-item">
      ${iocTypeBadge(i.ioc_type)}
      <span class="ioc-value" title="${escHtml(i.ioc_value)}">${escHtml(i.ioc_value)}</span>
      ${i.malware_family ? `<span class="text-xs" style="color:var(--medium);white-space:nowrap">${i.malware_family}</span>` : ''}
      <a href="/threat-detail.html?id=${i.threat_id}" class="text-xs text-muted" style="white-space:nowrap;max-width:140px;overflow:hidden;text-overflow:ellipsis">${i.threat_title?.slice(0,40)}</a>
      <span class="ioc-confidence">${i.confidence}%</span>
      <button class="copy-btn" onclick="copyToClipboard('${escAttr(i.ioc_value)}')" title="Copy">⎘</button>
    </div>
  `).join('');
}

function exportIocs() {
  const type = document.getElementById('f-ioc-type')?.value || '';
  const days = document.getElementById('f-ioc-days')?.value || '7';
  const params = new URLSearchParams({ days, min_confidence: 0, limit: 10000 });
  if (type) params.set('type', type);

  fetch(`/api/iocs?${params}`).then(r => r.json()).then(data => {
    const csv = 'type,value,confidence,malware_family,context,threat_title,severity\n' +
      (data.iocs || []).map(i =>
        `${i.ioc_type},"${i.ioc_value}",${i.confidence},"${i.malware_family || ''}","${i.context || ''}","${i.threat_title || ''}",${i.severity}`
      ).join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = `iocs-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
    toast(`Exported ${data.iocs?.length || 0} IOCs`, 'success');
  });
}

function escHtml(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function escAttr(s) { return (s||'').replace(/'/g,"\\'"); }

loadIocs();
setInterval(loadIocs, 60000);
