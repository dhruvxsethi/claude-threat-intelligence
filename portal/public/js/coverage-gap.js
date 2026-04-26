let _gapDays = 7;

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function setGapDays(days, btn) {
  _gapDays = days;
  document.querySelectorAll('.time-pill').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  loadCoverageGap();
}

async function loadCoverageGap() {
  const d = await fetch(`/api/coverage-gap?days=${_gapDays}&limit=100`).then(r => r.json());
  setText('cg-article', d.summary?.article_sourced ?? 0);
  setText('cg-unique', d.summary?.not_seen_elsewhere ?? 0);
  setText('cg-seen', d.summary?.seen_elsewhere ?? 0);
  setText('cg-first', d.summary?.seen_by_us_first ?? 0);
  renderProviders(d.providers || []);
  renderGapRows(d.threats || []);
}

function renderProviders(providers) {
  const el = document.getElementById('coverage-providers');
  if (!el) return;
  if (!providers.length) {
    el.innerHTML = '<div class="empty"><div class="empty-title">No external coverage imported yet</div><div class="empty-sub">Use Sync Coverage to compare against NVD, CISA KEV, GitHub advisories, MalwareBazaar, URLHaus, and optional Shodan/Censys.</div></div>';
    return;
  }
  el.innerHTML = providers.map(p => `<div class="coverage-provider">
    <span class="coverage-provider-name">${esc(p.provider)}</span>
    <span class="coverage-provider-count">${p.count}</span>
  </div>`).join('');
}

function renderGapRows(threats) {
  const el = document.getElementById('coverage-gap-list');
  if (!el) return;
  if (!threats.length) {
    el.innerHTML = '<div class="empty"><div class="empty-title">No article-sourced threats in this window</div></div>';
    return;
  }

  el.innerHTML = threats.map(t => {
    const coverage = t.coverage || {};
    const confidence = coverage.confidence?.level
      ? `${coverage.confidence.level} confidence (${coverage.confidence.score})`
      : 'confidence not scored';
    const status = coverage.status === 'unique_candidate'
      ? '<span class="coverage-chip unique">not seen elsewhere</span>'
      : '<span class="coverage-chip seen">seen elsewhere</span>';
    const seen = [...(coverage.external_providers || []), ...(coverage.seen_groups || [])];
    const evidence = (t.evidence || []).slice(0, 3).map(e => `<div class="gap-evidence">
      <div class="gap-evidence-title">${esc(e.title || e.evidence_type || 'Evidence')}</div>
      <div class="gap-evidence-body">${esc((e.body || '').slice(0, 280))}</div>
      ${e.url ? `<a class="card-link" href="${esc(e.url)}" target="_blank" rel="noreferrer">Open source</a>` : ''}
    </div>`).join('');

    return `<div class="gap-row">
      <div class="gap-row-head">
        <div>
          <div class="gap-title"><a href="/threat-detail.html?id=${t.id}">${esc(t.title)}</a></div>
          <div class="gap-meta">${esc(t.source_name || 'Unknown source')} · first seen ${fmtDate(t.first_seen_by_us_at || t.ingested_at)}</div>
        </div>
        <div class="gap-status">${sevBadge(t.severity)} ${status}</div>
      </div>
      <div class="gap-summary">${esc(t.summary || '')}</div>
      <div class="gap-facts">
        <span>${t.cve_count || 0} CVEs</span>
        <span>${t.ioc_count || 0} IOCs</span>
        <span>${t.actor_count || 0} actors</span>
        <span>${esc(confidence)}</span>
        <span>${seen.length ? `Seen in ${seen.map(esc).join(', ')}` : 'No monitored/common match'}</span>
      </div>
      <div class="gap-evidence-grid">${evidence}</div>
    </div>`;
  }).join('');
}

async function syncExternal() {
  try {
    await fetch('/api/external/sync', { method: 'POST', headers: {'Content-Type':'application/json'}, body: '{}' });
    toast('Coverage sync started');
  } catch {
    toast('Failed to start coverage sync', 'warning');
  }
}

function downloadDemoReport() {
  window.location.href = `/api/reports/demo?days=${_gapDays}`;
}

loadCoverageGap();
setInterval(loadCoverageGap, 30000);
connectSse(null, loadCoverageGap);
