let _mapDays = 1;
let _mapData = { events: [], daily: [], routes: [], targets: [] };
let _mapFrame = 0;
let _selectedCountry = '';
let _targetHitZones = [];

const MAP_COLORS = {
  Malware: '#ff3045',
  Phishing: '#a855f7',
  Exploit: '#f5b331',
  Intrusion: '#4f8ef7',
};

const LAND_POLYGONS = [
  // North America
  [[-168, 72], [-142, 72], [-125, 61], [-110, 54], [-92, 50], [-76, 57], [-54, 51], [-58, 39], [-75, 29], [-83, 18], [-97, 15], [-112, 23], [-124, 33], [-137, 46], [-160, 56]],
  // Central America
  [[-112, 30], [-92, 24], [-80, 18], [-77, 8], [-86, 7], [-96, 15], [-108, 21]],
  // South America
  [[-81, 12], [-68, 8], [-55, -4], [-39, -18], [-46, -36], [-55, -55], [-68, -52], [-75, -30], [-80, -10]],
  // Greenland
  [[-73, 82], [-24, 82], [-20, 65], [-44, 59], [-62, 63], [-75, 72]],
  // Europe
  [[-12, 59], [2, 70], [27, 70], [43, 59], [39, 45], [25, 37], [5, 36], [-10, 43]],
  // Africa
  [[-18, 35], [9, 37], [33, 31], [51, 12], [43, -34], [20, -35], [5, -21], [-13, -5], [-17, 16]],
  // Asia
  [[33, 70], [70, 76], [112, 73], [150, 61], [166, 48], [153, 30], [132, 18], [117, 4], [94, 6], [76, 19], [57, 22], [42, 37], [34, 53]],
  // Middle East / India
  [[37, 34], [58, 30], [77, 24], [89, 22], [88, 8], [76, 6], [67, 16], [52, 16], [42, 25]],
  // Southeast Asia
  [[96, 23], [121, 22], [145, 8], [141, -8], [115, -7], [101, 6]],
  // Australia
  [[112, -11], [153, -11], [156, -29], [138, -44], [115, -35], [109, -23]],
  // Japan / Korea
  [[126, 41], [145, 45], [146, 31], [130, 31]],
];

function setMapDays(days, btn) {
  _mapDays = days;
  document.querySelectorAll('.tm-window .time-pill').forEach(b => b.classList.remove('active'));
  btn?.classList.add('active');
  loadThreatMap();
}

async function loadThreatMap() {
  _mapData = await fetch(`/api/threat-map?days=${_mapDays}`).then(r => r.json());
  _mapData.routes = buildRoutes(_mapData.events || []);
  _mapData.targets = buildTargets(_mapData.events || []);

  setText('tm-count', _mapData.summary?.events ?? 0);
  renderCountryRank(_mapData.top_countries || []);
  renderRank('tm-industries', _mapData.top_industries || [], 'industry');
  renderRank('tm-types', _mapData.top_types || [], 'kind');
  renderQuality(_mapData.summary || {});
  renderFeed(_mapData.events || []);
}

function buildRoutes(events) {
  const routes = new Map();
  for (const event of events) {
    if (!event.source || !event.target || event.source_country === event.target_country) continue;
    const key = `${event.source_country}->${event.target_country}->${event.kind}`;
    const row = routes.get(key) || {
      source_country: event.source_country,
      target_country: event.target_country,
      source: event.source,
      target: event.target,
      kind: event.kind,
      count: 0,
      ids: [],
      latest: event.time,
    };
    row.count += 1;
    row.ids.push(event.id);
    row.latest = row.latest > event.time ? row.latest : event.time;
    routes.set(key, row);
  }
  return [...routes.values()].sort((a, b) => b.count - a.count || String(b.latest).localeCompare(String(a.latest))).slice(0, 10);
}

function buildTargets(events) {
  const targets = new Map();
  for (const event of events) {
    if (!event.target) continue;
    const key = `${event.target_country}->${event.kind}`;
    const row = targets.get(key) || {
      target_country: event.target_country,
      target: event.target,
      kind: event.kind,
      count: 0,
      latest: event.time,
    };
    row.count += 1;
    row.latest = row.latest > event.time ? row.latest : event.time;
    targets.set(key, row);
  }
  return [...targets.values()].sort((a, b) => b.count - a.count || String(b.latest).localeCompare(String(a.latest))).slice(0, 18);
}

function renderRank(id, rows, key) {
  const el = document.getElementById(id);
  if (!el) return;
  if (!rows.length) {
    el.innerHTML = '<div class="text-xs text-3">No data yet</div>';
    return;
  }
  el.innerHTML = rows.slice(0, 4).map(r => `<div class="tm-rank-row">
    <span>${esc(r[key] || r.country || r.industry || r.kind || 'Unknown')}</span>
    <b>${r.count}</b>
  </div>`).join('');
}

function renderCountryRank(rows) {
  const el = document.getElementById('tm-countries');
  if (!el) return;
  if (!rows.length) {
    el.innerHTML = '<div class="text-xs text-3">No data yet</div>';
    return;
  }
  el.innerHTML = rows.slice(0, 4).map(r => {
    const country = r.country || 'Unknown';
    const active = country === _selectedCountry ? ' active' : '';
    return `<button type="button" class="tm-rank-row tm-country-row${active}" data-country="${escAttr(country)}">
      <span>${esc(country)}</span>
      <b>${r.count}</b>
    </button>`;
  }).join('');
}

function renderQuality(summary) {
  const el = document.getElementById('tm-quality');
  if (!el) return;
  const total = Math.max(1, summary.events || 0);
  const rows = [
    ['Actor-origin routes', summary.routed || 0],
    ['Target pulses', summary.targeted || 0],
    ['Article sourced', summary.article_sourced || 0],
  ];
  el.innerHTML = rows.map(([label, count]) => {
    const pct = Math.round((count / total) * 100);
    return `<div class="tm-quality-row">
      <span>${label}</span><b>${count}</b>
      <div class="tm-quality-bar"><span class="tm-quality-fill" style="--w:${pct}%"></span></div>
    </div>`;
  }).join('');
}

function renderFeed(events) {
  const el = document.getElementById('tm-live-feed');
  if (!el) return;
  const rows = _selectedCountry
    ? events.filter(e => e.target_country === _selectedCountry || e.source_country === _selectedCountry)
    : events;
  setText('tm-feed-title', _selectedCountry ? `Observations: ${_selectedCountry}` : 'Recent Radar Observations');
  if (!rows.length) {
    el.innerHTML = '<div class="text-xs text-3">No mapped observations yet</div>';
    return;
  }
  el.innerHTML = rows.slice(0, 9).map(e => {
    const path = e.source_country ? `${esc(e.source_country)} -> ${esc(e.target_country)}` : `Target: ${esc(e.target_country || 'Unknown')}`;
    const kind = esc(e.kind || 'Observation');
    return `<a class="tm-event" href="/threat-detail.html?id=${e.id}">
      <span class="tm-event-beacon ${String(e.kind || '').toLowerCase()}"></span>
      <span class="tm-event-body">
        <span class="tm-event-top">
          <b>${esc(e.title || 'Threat observation')}</b>
          <em>${kind}</em>
        </span>
        <small>${path} · ${esc(e.location_basis || 'mapped')} · ${relTime(e.time)}</small>
      </span>
    </a>`;
  }).join('');
}

function selectMapCountry(country = '') {
  _selectedCountry = _selectedCountry === country ? '' : country;
  renderCountryRank(_mapData.top_countries || []);
  renderFeed(_mapData.events || []);
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
  const nextW = Math.floor(rect.width * dpr);
  const nextH = Math.floor(rect.height * dpr);
  if (canvas.width !== nextW || canvas.height !== nextH) {
    canvas.width = nextW;
    canvas.height = nextH;
  }
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const w = rect.width;
  const h = rect.height;
  ctx.clearRect(0, 0, w, h);

  drawGrid(ctx, w, h);
  drawContinents(ctx, w, h);
  drawTargets(ctx, w, h, _mapData.targets || []);
  drawRoutes(ctx, w, h, _mapData.routes || []);
  drawTargetLabels(ctx, _targetHitZones);
  _mapFrame += 1;
  requestAnimationFrame(drawMap);
}

function drawGrid(ctx, w, h) {
  ctx.strokeStyle = 'rgba(255, 48, 96, 0.06)';
  ctx.lineWidth = 1;
  for (let x = 0; x < w; x += w / 10) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
  }
  for (let y = 0; y < h; y += h / 6) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }
}

function drawContinents(ctx, w, h) {
  drawLandOutlines(ctx, w, h);
  for (let lon = -178; lon <= 180; lon += 4.2) {
    for (let lat = -56; lat <= 78; lat += 3.8) {
      if (!isLand(lon, lat)) continue;
      const p = project(lat, lon, w, h);
      const opacity = 0.28 + ((Math.sin(lon * 0.71 + lat * 0.37) + 1) * 0.08);
      ctx.fillStyle = `rgba(185, 190, 205, ${opacity.toFixed(2)})`;
      ctx.beginPath();
      ctx.arc(p.x, p.y, 1.45, 0, Math.PI * 2);
      ctx.fill();
    }
  }
}

function drawLandOutlines(ctx, w, h) {
  ctx.strokeStyle = 'rgba(185, 190, 205, 0.12)';
  ctx.lineWidth = 1;
  for (const polygon of LAND_POLYGONS) {
    ctx.beginPath();
    polygon.forEach(([lon, lat], idx) => {
      const p = project(lat, lon, w, h);
      if (idx === 0) ctx.moveTo(p.x, p.y);
      else ctx.lineTo(p.x, p.y);
    });
    ctx.closePath();
    ctx.stroke();
  }
}

function isLand(lon, lat) {
  return LAND_POLYGONS.some(polygon => pointInPolygon(lon, lat, polygon));
}

function pointInPolygon(lon, lat, polygon) {
  let inside = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const [xi, yi] = polygon[i];
    const [xj, yj] = polygon[j];
    const intersects = ((yi > lat) !== (yj > lat))
      && (lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi);
    if (intersects) inside = !inside;
  }
  return inside;
}

function drawTargets(ctx, w, h, targets) {
  const max = Math.max(1, ...targets.map(t => t.count));
  _targetHitZones = [];
  for (let i = targets.length - 1; i >= 0; i--) {
    const t = targets[i];
    const p = project(t.target.lat, t.target.lon, w, h);
    const color = MAP_COLORS[t.kind] || MAP_COLORS.Intrusion;
    const size = 5 + Math.sqrt(t.count / max) * 12;
    const phase = ((_mapFrame / 150) + i * 0.11) % 1;
    const selected = t.target_country === _selectedCountry;
    drawTargetPulse(ctx, p.x, p.y, color, size, phase, selected);
    _targetHitZones.push({
      x: p.x,
      y: p.y,
      radius: Math.max(18, size + 12),
      color,
      size,
      count: t.count,
      country: t.target_country,
      selected,
    });
  }
}

function drawRoutes(ctx, w, h, routes) {
  const max = Math.max(1, ...routes.map(r => r.count));
  routes.forEach((route, i) => {
    const a = project(route.source.lat, route.source.lon, w, h);
    const b = project(route.target.lat, route.target.lon, w, h);
    const color = MAP_COLORS[route.kind] || MAP_COLORS.Intrusion;
    const width = 1.2 + (route.count / max) * 3.5;
    const phase = ((_mapFrame / 220) + i * 0.19) % 1;
    drawRoute(ctx, a, b, color, width, i < 4 ? phase : null);
  });
}

function drawRoute(ctx, a, b, color, width, phase) {
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2 - Math.min(120, Math.abs(a.x - b.x) * 0.14 + 26);
  ctx.strokeStyle = color;
  ctx.globalAlpha = 0.42;
  ctx.lineWidth = width;
  ctx.beginPath();
  ctx.moveTo(a.x, a.y);
  ctx.quadraticCurveTo(mx, my, b.x, b.y);
  ctx.stroke();

  if (phase !== null) {
    const x = (1 - phase) * (1 - phase) * a.x + 2 * (1 - phase) * phase * mx + phase * phase * b.x;
    const y = (1 - phase) * (1 - phase) * a.y + 2 * (1 - phase) * phase * my + phase * phase * b.y;
    ctx.globalAlpha = 0.95;
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(x, y, Math.max(3.2, width + 1), 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.globalAlpha = 1;
}

function drawTargetPulse(ctx, x, y, color, size, phase, selected = false) {
  ctx.globalAlpha = 0.18;
  ctx.fillStyle = color;
  ctx.beginPath();
  ctx.arc(x, y, size * 1.9, 0, Math.PI * 2);
  ctx.fill();

  ctx.globalAlpha = 0.85 - phase * 0.45;
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.arc(x, y, size + phase * 12, 0, Math.PI * 2);
  ctx.stroke();

  ctx.globalAlpha = 0.95;
  ctx.fillStyle = color;
  ctx.beginPath();
  ctx.arc(x, y, Math.max(4, size * 0.55), 0, Math.PI * 2);
  ctx.fill();

  if (selected) {
    ctx.globalAlpha = 0.95;
    ctx.strokeStyle = '#e2e8f4';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.arc(x, y, size + 18, 0, Math.PI * 2);
    ctx.stroke();
  }
  ctx.globalAlpha = 1;
}

function drawTargetLabels(ctx, zones) {
  const labelZones = zones
    .filter(z => z.count >= 2 || z.selected)
    .sort((a, b) => a.y - b.y || a.x - b.x);
  for (const zone of labelZones) {
    const label = zone.country;
    const count = String(zone.count);
    const x = zone.x + zone.size + 9;
    const y = zone.y - 10;
    ctx.font = '700 12px Plus Jakarta Sans, sans-serif';
    const labelWidth = Math.max(ctx.measureText(label).width, ctx.measureText(count).width) + 16;
    ctx.fillStyle = 'rgba(6,8,14,0.82)';
    ctx.strokeStyle = 'rgba(255,255,255,0.1)';
    ctx.lineWidth = 1;
    roundRect(ctx, x - 6, y - 15, labelWidth, 35, 6);
    ctx.fill();
    ctx.stroke();
    ctx.fillStyle = '#f0f5ff';
    ctx.fillText(label, x, y - 1);
    ctx.font = '700 10px Plus Jakarta Sans, sans-serif';
    ctx.fillStyle = zone.color;
    ctx.fillText(count, x, y + 12);
  }
}

function roundRect(ctx, x, y, width, height, radius) {
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.arcTo(x + width, y, x + width, y + height, radius);
  ctx.arcTo(x + width, y + height, x, y + height, radius);
  ctx.arcTo(x, y + height, x, y, radius);
  ctx.arcTo(x, y, x + width, y, radius);
  ctx.closePath();
}

function bindMapInteractions() {
  const canvas = document.getElementById('tm-map');
  if (!canvas) return;
  canvas.addEventListener('click', event => {
    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;
    const hit = [..._targetHitZones]
      .sort((a, b) => b.count - a.count)
      .find(z => Math.hypot(z.x - x, z.y - y) <= z.radius);
    if (hit) selectMapCountry(hit.country);
  });
  canvas.addEventListener('mousemove', event => {
    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;
    const hit = _targetHitZones.find(z => Math.hypot(z.x - x, z.y - y) <= z.radius);
    canvas.style.cursor = hit ? 'pointer' : 'default';
  });
  document.getElementById('tm-countries')?.addEventListener('click', event => {
    const row = event.target.closest('.tm-country-row');
    if (row?.dataset.country) selectMapCountry(row.dataset.country);
  });
}

function escAttr(s) {
  return esc(s).replace(/"/g, '&quot;');
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

loadThreatMap();
bindMapInteractions();
setInterval(loadThreatMap, 45000);
connectSse(null, loadThreatMap);
requestAnimationFrame(drawMap);
