// ─── Shared utilities across all pages ───────────────────────────────────

// UTC clock
function updateClock() {
  const now = new Date();
  const t = now.toUTCString().split(' ')[4];
  document.getElementById('utc-clock').textContent = `${t} UTC`;
}
setInterval(updateClock, 1000);
updateClock();

// Toast notifications
function toast(msg, type = 'info') {
  const container = document.getElementById('toasts');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// Copy to clipboard
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => toast(`Copied: ${text.slice(0, 40)}`, 'success'));
}

// Severity badge HTML
function severityBadge(sev) {
  const map = {
    critical: '🔴 Critical',
    high: '🟠 High',
    medium: '🟡 Medium',
    low: '🟢 Low',
    unknown: '⚪ Unknown',
  };
  return `<span class="badge badge-${sev || 'unknown'}">${map[sev] || sev || 'Unknown'}</span>`;
}

// Sector badge HTML
function sectorBadge(sector) {
  const icons = { banking: '🏦', government: '🏛️', healthcare: '🏥' };
  return `<span class="badge badge-${sector}">${icons[sector] || ''} ${sector}</span>`;
}

// Relative time
function relativeTime(iso) {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

// Format date
function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-US', { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
}

// Credibility color
function credColor(score) {
  if (score >= 80) return 'var(--low)';
  if (score >= 60) return 'var(--medium)';
  if (score >= 40) return 'var(--high)';
  return 'var(--critical)';
}

// Credibility bar HTML
function credBar(score) {
  return `
    <div class="credibility-bar" title="${score}/100 credibility">
      <div class="credibility-fill" style="width:${score}%;background:${credColor(score)}"></div>
    </div>
    <div class="text-xs text-muted">${score}</div>
  `;
}

// IOC type colors
const IOC_COLORS = {
  ip: '#ef4444', ipv6: '#ef4444', domain: '#f97316', subdomain: '#fb923c',
  url: '#eab308', email: '#22c55e', hash_md5: '#3b82f6', hash_sha1: '#6366f1',
  hash_sha256: '#8b5cf6', hash_sha512: '#a855f7', file_name: '#06b6d4',
  file_path: '#0ea5e9', registry_key: '#64748b', mutex: '#94a3b8',
  user_agent: '#f59e0b', asn: '#84cc16', bitcoin_address: '#f97316',
  yara_rule: '#10b981',
};

function iocTypeBadge(type) {
  const color = IOC_COLORS[type] || '#6b7280';
  return `<span class="ioc-type" style="background:${color}20;color:${color};border:1px solid ${color}40">${type.replace('_', ' ')}</span>`;
}

// Trigger pipeline run
async function triggerPipeline(slot = null) {
  try {
    const res = await fetch('/api/pipeline/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ slot }),
    });
    const data = await res.json();
    toast(`Pipeline started (slot ${data.slot})`, 'success');
  } catch (e) {
    toast('Failed to start pipeline', 'warning');
  }
}

// SSE connection for real-time updates
function connectSse(onPipelineStart, onPipelineDone) {
  const es = new EventSource('/api/events');
  es.addEventListener('pipeline_started', e => {
    const data = JSON.parse(e.data);
    toast(`Pipeline running (slot ${data.slot})...`, 'info');
    if (onPipelineStart) onPipelineStart(data);
  });
  es.addEventListener('pipeline_done', e => {
    const data = JSON.parse(e.data);
    toast(`Pipeline done — ${data.threats_created} new threats`, 'success');
    if (onPipelineDone) onPipelineDone(data);
  });
  es.onerror = () => es.close();
  return es;
}

// Threat type label
function threatTypeLabel(type) {
  const map = {
    ransomware: 'Ransomware', apt: 'APT', phishing: 'Phishing',
    vulnerability: 'Vulnerability', data_breach: 'Data Breach',
    supply_chain: 'Supply Chain', zero_day: 'Zero Day', ddos: 'DDoS',
    cryptojacking: 'Cryptojacking', malware: 'Malware', fraud: 'Fraud',
    espionage: 'Espionage', insider_threat: 'Insider Threat', other: 'Other',
  };
  return map[type] || type || 'Unknown';
}

// Global search (used on dashboard)
let searchTimeout;
function globalSearch(query) {
  clearTimeout(searchTimeout);
  const overlay = document.getElementById('search-overlay');
  if (!query || query.length < 2) {
    if (overlay) overlay.classList.add('hidden');
    return;
  }
  searchTimeout = setTimeout(async () => {
    const res = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
    const data = await res.json();
    if (overlay) {
      overlay.classList.remove('hidden');
      renderSearchResults(data, overlay);
    }
  }, 300);
}

function renderSearchResults(data, container) {
  const el = container.querySelector('#search-results') || container;
  let html = '';

  if (data.threats?.length) {
    html += `<div class="text-xs text-muted mb-2">THREATS</div>`;
    html += data.threats.slice(0, 5).map(t =>
      `<div style="padding:6px 0;border-bottom:1px solid var(--border)">
        <a href="/threat-detail.html?id=${t.id}" style="color:var(--text);font-size:0.82rem">${t.title}</a>
        <span style="margin-left:8px">${severityBadge(t.severity)}</span>
      </div>`
    ).join('');
  }

  if (data.cves?.length) {
    html += `<div class="text-xs text-muted mt-3 mb-2">CVEs</div>`;
    html += data.cves.slice(0, 3).map(c =>
      `<div style="padding:4px 0;font-family:var(--font-mono);font-size:0.8rem;color:var(--critical)">
        <a href="/threat-detail.html?id=${c.threat_id}">${c.cve_id}</a>
        <span style="color:var(--text-muted);margin-left:8px">${c.cvss_score || 'N/A'}</span>
      </div>`
    ).join('');
  }

  if (!data.threats?.length && !data.cves?.length) {
    html = `<div class="text-sm text-muted">No results found</div>`;
  }

  el.innerHTML = html;
}

// Close search on outside click
document.addEventListener('click', e => {
  const overlay = document.getElementById('search-overlay');
  if (overlay && !overlay.contains(e.target) && e.target.id !== 'global-search') {
    overlay.classList.add('hidden');
  }
});
