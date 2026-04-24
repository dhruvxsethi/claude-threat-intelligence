// Threat Feed page

let currentPage = 1;
let currentSort = 'ingested_at';
let currentOrder = 'desc';
let searchQuery = '';

function getFilters() {
  return {
    severity: document.getElementById('f-severity')?.value || '',
    sector: document.getElementById('f-sector')?.value || '',
    threat_type: document.getElementById('f-type')?.value || '',
    days: document.getElementById('f-days')?.value || '7',
    has_cves: document.getElementById('f-has-cves')?.checked ? 'true' : '',
    has_iocs: document.getElementById('f-has-iocs')?.checked ? 'true' : '',
    search: searchQuery,
  };
}

async function loadThreats(page = 1) {
  currentPage = page;
  const f = getFilters();
  const params = new URLSearchParams({
    page,
    limit: 25,
    sort: currentSort,
    order: currentOrder,
    days: f.days,
    ...(f.severity && { severity: f.severity }),
    ...(f.sector && { sector: f.sector }),
    ...(f.threat_type && { threat_type: f.threat_type }),
    ...(f.has_cves && { has_cves: 'true' }),
    ...(f.has_iocs && { has_iocs: 'true' }),
    ...(f.search && { search: f.search }),
  });

  const res = await fetch(`/api/threats?${params}`);
  const data = await res.json();

  renderThreats(data.threats || []);
  renderPagination(data.pages, data.page, data.total);
}

function renderThreats(threats) {
  const tbody = document.getElementById('threats-tbody');
  const countEl = document.getElementById('results-count');
  if (countEl) countEl.textContent = `${threats.length} results`;

  if (!threats.length) {
    tbody.innerHTML = `<tr><td colspan="8">
      <div class="empty-state">
        <div class="empty-icon">🛡</div>
        <div class="empty-title">No threats found</div>
        <div class="empty-sub">Adjust your filters or run the pipeline.</div>
      </div>
    </td></tr>`;
    return;
  }

  tbody.innerHTML = threats.map(t => `
    <tr>
      <td>${severityBadge(t.severity)}</td>
      <td>
        <a class="threat-title-link" href="/threat-detail.html?id=${t.id}">${escHtml(t.title)}</a>
        <div class="threat-meta">${escHtml(t.source_name)} · ${relativeTime(t.published_at)}</div>
      </td>
      <td>${(t.sectors || []).map(sectorBadge).join(' ')}</td>
      <td><span class="text-xs text-dim">${threatTypeLabel(t.threat_type)}</span></td>
      <td>
        <div class="flex gap-2 items-center">
          ${credBar(t.credibility_score)}
        </div>
      </td>
      <td>
        ${t.ioc_count > 0 ? `<span class="badge badge-ioc">${t.ioc_count} IOC${t.ioc_count !== 1 ? 's' : ''}</span>` : '<span class="text-muted text-xs">—</span>'}
      </td>
      <td>
        ${t.cve_count > 0 ? `<span class="badge badge-cve">${t.cve_count} CVE${t.cve_count !== 1 ? 's' : ''}</span>` : '<span class="text-muted text-xs">—</span>'}
      </td>
      <td class="text-muted text-xs font-mono">${fmtDate(t.ingested_at)}</td>
    </tr>
  `).join('');
}

function renderPagination(pages, current, total) {
  const el = document.getElementById('pagination');
  if (!el || pages <= 1) { if (el) el.innerHTML = ''; return; }

  let html = `<button class="page-btn" onclick="loadThreats(${current - 1})" ${current <= 1 ? 'disabled' : ''}>‹</button>`;

  for (let i = 1; i <= Math.min(pages, 10); i++) {
    html += `<button class="page-btn ${i === current ? 'active' : ''}" onclick="loadThreats(${i})">${i}</button>`;
  }
  if (pages > 10) html += `<span class="text-muted text-xs">… ${pages} pages</span>`;

  html += `<button class="page-btn" onclick="loadThreats(${current + 1})" ${current >= pages ? 'disabled' : ''}>›</button>`;
  html += `<span class="text-xs text-muted">${total} total</span>`;

  el.innerHTML = html;
}

function applyFilters() { loadThreats(1); }

let filterTimeout;
function filterThreats(q) {
  clearTimeout(filterTimeout);
  filterTimeout = setTimeout(() => {
    searchQuery = q;
    loadThreats(1);
  }, 300);
}

function sortBy(col) {
  if (currentSort === col) {
    currentOrder = currentOrder === 'desc' ? 'asc' : 'desc';
  } else {
    currentSort = col;
    currentOrder = 'desc';
  }
  loadThreats(1);
}

function escHtml(str) {
  return (str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// Init
loadThreats();
setInterval(() => loadThreats(currentPage), 30000);
connectSse(null, () => loadThreats(1));
