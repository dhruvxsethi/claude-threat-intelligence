// Toast
function toast(msg, type = 'info') {
  const wrap = document.getElementById('toasts');
  if (!wrap) return;
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  wrap.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// Copy
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => toast(`Copied: ${text.slice(0, 48)}`, 'success'));
}

// Severity badge
function sevBadge(sev) {
  const map = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', unknown: 'Unknown' };
  return `<span class="badge badge-${sev || 'unknown'}">${map[sev] || sev || 'Unknown'}</span>`;
}

// Sector badge
function secBadge(s) {
  const labels = { banking: 'Banking', government: 'Government', healthcare: 'Healthcare' };
  return `<span class="badge badge-${s}">${labels[s] || s}</span>`;
}

// Time helpers
function relTime(iso) {
  if (!iso) return '—';
  const m = Math.floor((Date.now() - new Date(iso)) / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// Credibility
function credColor(n) {
  if (n >= 80) return 'var(--low)';
  if (n >= 60) return 'var(--medium)';
  if (n >= 40) return 'var(--high)';
  return 'var(--critical)';
}

function credBar(score) {
  return `<div class="cred-wrap">
    <div class="cred-bar"><div class="cred-fill" style="width:${score}%;background:${credColor(score)}"></div></div>
    <span class="cred-num">${score}</span>
  </div>`;
}

// IOC type colors
const IOC_COLORS = {
  ip:'#f85149', ipv6:'#f85149', domain:'#e3b341', subdomain:'#d29922',
  url:'#d29922', email:'#3fb950', hash_md5:'#58a6ff', hash_sha1:'#8b74ff',
  hash_sha256:'#bc8cff', hash_sha512:'#d3b5ff', file_name:'#22d3ee',
  file_path:'#0ea5e9', registry_key:'#64748b', mutex:'#94a3b8',
  user_agent:'#f59e0b', asn:'#84cc16', bitcoin_address:'#e3b341', yara_rule:'#3fb950',
};

function iocPill(type) {
  const c = IOC_COLORS[type] || '#6b7280';
  return `<span class="ioc-type-pill" style="background:${c}22;color:${c};border:1px solid ${c}44">${type.replace(/_/g,' ')}</span>`;
}

// Threat type label
function typeLabel(t) {
  const m = {
    ransomware:'Ransomware', apt:'APT', phishing:'Phishing', vulnerability:'Vulnerability',
    data_breach:'Data Breach', supply_chain:'Supply Chain', zero_day:'Zero Day', ddos:'DDoS',
    cryptojacking:'Cryptojacking', malware:'Malware', fraud:'Fraud', espionage:'Espionage',
    insider_threat:'Insider', other:'Other',
  };
  return m[t] || t || '—';
}

// Escape HTML
function esc(s) {
  return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// Trigger pipeline sync
async function triggerPipeline() {
  try {
    const r = await fetch('/api/pipeline/run', { method:'POST', headers:{'Content-Type':'application/json'}, body:'{}' });
    const d = await r.json();
    toast('Sync started — new threats will appear automatically', 'success');
  } catch { toast('Failed to start sync', 'warning'); }
}

// SSE
function connectSse(onStart, onDone) {
  try {
    const es = new EventSource('/api/events');
    es.addEventListener('pipeline_started', e => {
      toast('Syncing feeds…', 'info');
      if (onStart) onStart(JSON.parse(e.data));
    });
    es.addEventListener('pipeline_done', e => {
      const d = JSON.parse(e.data);
      toast(`Sync complete — ${d.threats_created||0} new threats`, 'success');
      if (onDone) onDone(d);
    });
    es.onerror = () => es.close();
  } catch {}
}

// Global search
let _st;
function globalSearch(q) {
  clearTimeout(_st);
  const ov = document.getElementById('search-overlay');
  if (!q || q.length < 2) { if (ov) ov.classList.add('hidden'); return; }
  _st = setTimeout(async () => {
    const d = await fetch(`/api/search?q=${encodeURIComponent(q)}`).then(r=>r.json());
    if (!ov) return;
    ov.classList.remove('hidden');
    const el = document.getElementById('search-results');
    if (!el) return;
    let html = '';
    if (d.threats?.length) {
      html += `<div class="text-xs text-3 mb-2">THREATS</div>`;
      html += d.threats.slice(0,6).map(t=>`<div style="padding:6px 0;border-bottom:1px solid var(--border)"><a href="/threat-detail.html?id=${t.id}" style="color:var(--text);font-size:0.82rem;font-weight:500">${esc(t.title)}</a> ${sevBadge(t.severity)}</div>`).join('');
    }
    if (d.cves?.length) {
      html += `<div class="text-xs text-3 mt-3 mb-2">CVEs</div>`;
      html += d.cves.slice(0,4).map(c=>`<a href="/threat-detail.html?id=${c.threat_id}" style="display:block;padding:4px 0;font-family:var(--mono);font-size:0.78rem;color:var(--critical)">${c.cve_id} <span style="color:var(--text-3)">${c.cvss_score||'N/A'}</span></a>`).join('');
    }
    if (!d.threats?.length && !d.cves?.length) html = `<div class="text-sm text-3">No results found</div>`;
    el.innerHTML = html;
  }, 300);
}

document.addEventListener('click', e => {
  const ov = document.getElementById('search-overlay');
  if (ov && !ov.contains(e.target) && e.target.id !== 'global-search') ov.classList.add('hidden');
});
