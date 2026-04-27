let _mapDays = 1;
let _mapData = { events: [], daily: [] };
let _mapFrame = 0;

const MAP_COLORS = {
  Malware: '#ff3045',
  Phishing: '#a855f7',
  Exploit: '#f5b331',
  Intrusion: '#4f8ef7',
};

const CONTINENT_DOTS = [
  [-155, 62, -55, 15], [-125, 50, -70, 25], [-82, 15, -35, -55],
  [-10, 58, 42, 35], [-17, 34, 52, -34], [35, 65, 160, 5],
  [68, 35, 118, 8], [95, 20, 145, -8], [112, -10, 155, -44],
];

function setMapDays(days, btn) {
  _mapDays = days;
  document.querySelectorAll('.tm-window .time-pill').forEach(b => b.classList.remove('active'));
  btn?.classList.add('active');
  loadThreatMap();
}

async function loadThreatMap() {
  _mapData = await fetch(`/api/threat-map?days=${_mapDays}`).then(r => r.json());
  setText('tm-count', _mapData.summary?.events ?? 0);
  renderRank('tm-countries', _mapData.top_countries || [], 'country');
  renderRank('tm-industries', _mapData.top_industries || [], 'industry');
  renderRank('tm-types', _mapData.top_types || [], 'kind');
  renderFeed(_mapData.events || []);
  drawSpark(_mapData.daily || []);
}

function renderRank(id, rows, key) {
  const el = document.getElementById(id);
  if (!el) return;
  if (!rows.length) {
    el.innerHTML = '<div class="text-xs text-3">No data yet</div>';
    return;
  }
  el.innerHTML = rows.map(r => `<div class="tm-rank-row">
    <span>${esc(r[key] || r.country || r.industry || r.kind || 'Unknown')}</span>
    <b>${r.count}</b>
  </div>`).join('');
}

function renderFeed(events) {
  const el = document.getElementById('tm-live-feed');
  if (!el) return;
  if (!events.length) {
    el.innerHTML = '<div class="text-xs text-3">No mapped observations yet</div>';
    return;
  }
  el.innerHTML = events.slice(0, 8).map(e => `<a class="tm-event" href="/threat-detail.html?id=${e.id}">
    <span class="tm-event-beacon ${e.kind.toLowerCase()}"></span>
    <span>
      <b>${esc(e.title || 'Threat observation')}</b>
      <small>${esc(e.source_country)} → ${esc(e.target_country)} · ${esc(e.kind)} · ${relTime(e.time)}</small>
    </span>
  </a>`).join('');
}

function project(lat, lon, width, height) {
  return {
    x: ((lon + 180) / 360) * width,
    y: ((90 - lat) / 180) * height,
  };
}

function drawMap() {
  const canvas = document.getElementById('tm-map');
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  if (canvas.width !== Math.floor(rect.width * dpr) || canvas.height !== Math.floor(rect.height * dpr)) {
    canvas.width = Math.floor(rect.width * dpr);
    canvas.height = Math.floor(rect.height * dpr);
  }
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const w = rect.width;
  const h = rect.height;
  ctx.clearRect(0, 0, w, h);
  drawGrid(ctx, w, h);
  drawContinents(ctx, w, h);
  drawEvents(ctx, w, h, _mapData.events || []);
  _mapFrame += 1;
  requestAnimationFrame(drawMap);
}

function drawGrid(ctx, w, h) {
  ctx.strokeStyle = 'rgba(255, 48, 96, 0.08)';
  ctx.lineWidth = 1;
  for (let x = 0; x < w; x += w / 12) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
  }
  for (let y = 0; y < h; y += h / 8) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }
}

function drawContinents(ctx, w, h) {
  ctx.fillStyle = 'rgba(185, 190, 205, 0.35)';
  for (const [lon1, lat1, lon2, lat2] of CONTINENT_DOTS) {
    for (let lon = lon1; lon <= lon2; lon += 4.2) {
      for (let lat = lat2; lat <= lat1; lat += 3.7) {
        const noise = Math.sin(lon * 7.13 + lat * 3.91) + Math.cos(lon * 2.11);
        if (noise < -0.35) continue;
        const p = project(lat, lon, w, h);
        ctx.beginPath();
        ctx.arc(p.x, p.y, 1.8, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }
}

function drawEvents(ctx, w, h, events) {
  const now = _mapFrame / 90;
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    const a = project(e.source.lat, e.source.lon, w, h);
    const b = project(e.target.lat, e.target.lon, w, h);
    const color = MAP_COLORS[e.kind] || MAP_COLORS.Intrusion;
    const phase = (now + i * 0.13) % 1;
    drawArc(ctx, a, b, color, phase);
    drawPulse(ctx, b.x, b.y, color, phase);
  }
}

function drawArc(ctx, a, b, color, phase) {
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2 - Math.min(130, Math.abs(a.x - b.x) * 0.18 + 40);
  ctx.strokeStyle = color;
  ctx.globalAlpha = 0.22;
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.moveTo(a.x, a.y);
  ctx.quadraticCurveTo(mx, my, b.x, b.y);
  ctx.stroke();
  const t = phase;
  const x = (1 - t) * (1 - t) * a.x + 2 * (1 - t) * t * mx + t * t * b.x;
  const y = (1 - t) * (1 - t) * a.y + 2 * (1 - t) * t * my + t * t * b.y;
  ctx.globalAlpha = 0.95;
  ctx.fillStyle = color;
  ctx.beginPath();
  ctx.arc(x, y, 3.2, 0, Math.PI * 2);
  ctx.fill();
  ctx.globalAlpha = 1;
}

function drawPulse(ctx, x, y, color, phase) {
  const r = 8 + phase * 22;
  ctx.strokeStyle = color;
  ctx.globalAlpha = 1 - phase;
  ctx.lineWidth = 3;
  ctx.beginPath();
  ctx.arc(x, y, r, 0, Math.PI * 2);
  ctx.stroke();
  ctx.globalAlpha = 0.95;
  ctx.fillStyle = color;
  ctx.beginPath();
  ctx.arc(x, y, 4.5, 0, Math.PI * 2);
  ctx.fill();
  ctx.globalAlpha = 1;
}

function drawSpark(rows) {
  const canvas = document.getElementById('tm-spark');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  const values = rows.length ? rows.map(r => r.count) : [0];
  const max = Math.max(1, ...values);
  ctx.fillStyle = 'rgba(255, 48, 96, 0.16)';
  ctx.strokeStyle = '#ff2f6d';
  ctx.lineWidth = 2;
  ctx.beginPath();
  values.forEach((v, i) => {
    const x = (i / Math.max(1, values.length - 1)) * w;
    const y = h - (v / max) * (h - 14) - 7;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();
  ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath(); ctx.fill();
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

loadThreatMap();
setInterval(loadThreatMap, 30000);
connectSse(null, loadThreatMap);
requestAnimationFrame(drawMap);
