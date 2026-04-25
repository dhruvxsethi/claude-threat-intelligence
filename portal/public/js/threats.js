let _page=1, _sort='ingested_at', _order='desc', _q='';

// Sync pill selection → hidden select → reload
function setFilterPill(btn, filter, val) {
  // Deactivate siblings in same group
  btn.closest('.filter-group').querySelectorAll('.filter-pill').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  // Sync hidden select
  const sel = document.getElementById('f-' + filter);
  if (sel) { sel.innerHTML = `<option value="${val}" selected></option>`; }
  loadThreats(1);
}

function setDaysPill(btn, days) {
  btn.closest('.time-pills').querySelectorAll('.time-pill').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const sel = document.getElementById('f-days');
  if (sel) { sel.innerHTML = `<option value="${days}" selected></option>`; }
  loadThreats(1);
}

function getF() {
  return {
    severity: document.getElementById('f-severity')?.value||'',
    sector: document.getElementById('f-sector')?.value||'',
    threat_type: document.getElementById('f-type')?.value||'',
    days: document.getElementById('f-days')?.value||'7',
    has_cves: document.getElementById('f-has-cves')?.checked?'true':'',
    has_iocs: document.getElementById('f-has-iocs')?.checked?'true':'',
    search: _q,
  };
}

async function loadThreats(page=1) {
  _page = page;
  const f = getF();
  const p = new URLSearchParams({ page, limit:25, sort:_sort, order:_order, days:f.days });
  if (f.severity) p.set('severity', f.severity);
  if (f.sector) p.set('sector', f.sector);
  if (f.threat_type) p.set('threat_type', f.threat_type);
  if (f.has_cves) p.set('has_cves','true');
  if (f.has_iocs) p.set('has_iocs','true');
  if (f.search) p.set('search', f.search);

  const d = await fetch(`/api/threats?${p}`).then(r=>r.json());
  renderRows(d.threats||[]);
  renderPager(d.pages, d.page, d.total);
  const cnt = document.getElementById('results-count');
  if (cnt) cnt.textContent = `${d.total} results`;
}

function renderRows(threats) {
  const tb = document.getElementById('threats-tbody');
  if (!threats.length) {
    tb.innerHTML = `<tr><td colspan="8"><div class="empty"><div class="empty-icon">🛡</div><div class="empty-title">No threats found</div><div class="empty-sub">Adjust filters or run the pipeline.</div></div></td></tr>`;
    return;
  }
  tb.innerHTML = threats.map(t=>`<tr>
    <td>${sevBadge(t.severity)}</td>
    <td class="cell-title">
      <a href="/threat-detail.html?id=${t.id}">${esc(t.title)}</a>
      <div class="cell-sub">${esc(t.source_name||'')} · ${relTime(t.published_at)}</div>
    </td>
    <td>${(t.sectors||[]).map(secBadge).join(' ')}</td>
    <td><span class="text-xs text-2">${typeLabel(t.threat_type)}</span></td>
    <td>${credBar(t.credibility_score)}</td>
    <td>${t.ioc_count>0?`<span class="badge badge-ioc">${t.ioc_count} IOC${t.ioc_count!==1?'s':''}</span>`:'<span class="text-3 text-xs">—</span>'}</td>
    <td>${t.cve_count>0?`<span class="badge badge-cve">${t.cve_count} CVE${t.cve_count!==1?'s':''}</span>`:'<span class="text-3 text-xs">—</span>'}</td>
    <td class="text-xs text-3 mono">${fmtDate(t.ingested_at)}</td>
  </tr>`).join('');
}

function renderPager(pages, cur, total) {
  const el = document.getElementById('pagination');
  if (!el || pages<=1) { if(el) el.innerHTML=''; return; }
  let h = `<button class="pg-btn" onclick="loadThreats(${cur-1})" ${cur<=1?'disabled':''}>‹</button>`;
  for (let i=1; i<=Math.min(pages,9); i++) h+=`<button class="pg-btn ${i===cur?'active':''}" onclick="loadThreats(${i})">${i}</button>`;
  if (pages>9) h+=`<span class="text-xs text-3">…${pages}</span>`;
  h+=`<button class="pg-btn" onclick="loadThreats(${cur+1})" ${cur>=pages?'disabled':''}>›</button>`;
  h+=`<span class="text-xs text-3">${total} total</span>`;
  el.innerHTML = h;
}

function applyFilters() { loadThreats(1); }
let _ft;
function filterThreats(q) { clearTimeout(_ft); _ft=setTimeout(()=>{_q=q;loadThreats(1);},300); }
function sortBy(col) { _sort===col?(_order=_order==='desc'?'asc':'desc'):(_sort=col,_order='desc'); loadThreats(1); }

loadThreats();
setInterval(()=>loadThreats(_page), 30000);
connectSse(null, ()=>loadThreats(1));
