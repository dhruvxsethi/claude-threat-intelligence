let _days = 30, _motiv = '', _soph = '', _search = '', _selected = null;
let _allActors = [];

const MOTIV_COLORS = {
  financial:    '#4ac97e',
  espionage:    '#a78bfa',
  sabotage:     '#f55252',
  hacktivism:   '#e8a44a',
  cyberwarfare: '#f55252',
  unknown:      '#4a5568',
};

const SOPH_LABEL = {
  nation_state:  'Nation-State',
  advanced:      'Advanced',
  intermediate:  'Intermediate',
  basic:         'Basic',
  script_kiddie: 'Script Kiddie',
  unknown:       'Unknown',
};

async function loadActors() {
  const p = new URLSearchParams({ days: _days });
  if (_search) p.set('search', _search);
  const d = await fetch('/api/actors?' + p).then(r => r.json());
  _allActors = d.actors || [];

  const nationState  = _allActors.filter(a => a.sophistication === 'nation_state').length;
  const countries    = new Set(_allActors.map(a => a.origin_country).filter(Boolean)).size;
  const totalThreats = _allActors.reduce((s, a) => s + (a.threat_count || 0), 0);
  document.getElementById('asb-total').textContent     = _allActors.length;
  document.getElementById('asb-nations').textContent   = nationState;
  document.getElementById('asb-countries').textContent = countries;
  document.getElementById('asb-threats').textContent   = totalThreats;

  renderGrid();
  renderCountryChart(d.summary?.by_country || []);
  renderMotivChart(d.summary?.by_motivation || []);
}

function applyFilters(actors) {
  return actors.filter(a => {
    if (_motiv && a.motivation !== _motiv) return false;
    if (_soph  && a.sophistication !== _soph) return false;
    return true;
  });
}

function renderGrid() {
  const el = document.getElementById('actor-grid');
  const visible = applyFilters(_allActors);

  if (!visible.length) {
    el.innerHTML = '<div class="empty"><div class="empty-icon">⬡</div><div class="empty-title">No actors found</div><div class="empty-sub">Try a wider time range or different filters.</div></div>';
    return;
  }

  el.innerHTML = '<div class="actor-grid">' + visible.map((a, i) => actorTile(a, i)).join('') + '</div>';

  // Attach click handlers after render — avoids JSON-in-onclick attribute escaping issues
  el.querySelectorAll('.actor-tile').forEach(function(tile) {
    const idx = parseInt(tile.dataset.idx, 10);
    tile.addEventListener('click', function() { selectActor(visible[idx]); });
  });

  if (_selected) {
    const tile = el.querySelector('[data-name="' + CSS.escape(_selected) + '"]');
    if (tile) tile.classList.add('selected');
  }
}

function actorTile(a, idx) {
  const sophCls   = 'soph-' + (a.sophistication || 'unknown');
  const sophLabel = SOPH_LABEL[a.sophistication] || a.sophistication || 'Unknown';
  const motivCls  = 'motiv-' + (a.motivation || 'unknown');

  const countryTag = a.origin_country
    ? '<span class="actor-tag country">' + esc(a.origin_country) + '</span>'
    : '';
  const motivTag = '<span class="actor-tag ' + motivCls + '">' + esc(a.motivation || 'unknown') + '</span>';
  const sophTag  = '<span class="actor-tag soph">' + esc(sophLabel) + '</span>';

  const aliases = a.aliases && a.aliases.length
    ? '<div class="actor-tile-aliases">aka: ' + a.aliases.slice(0, 4).map(esc).join(', ') + (a.aliases.length > 4 ? ' +' + (a.aliases.length - 4) : '') + '</div>'
    : '';

  const sectorBadges = [...new Set(a.sectors || [])].map(secBadge).join(' ');
  const sevDots = [...new Set(a.severities || [])].map(function(s) {
    return '<span class="sev-dot ' + s + '" style="width:7px;height:7px" title="' + s + '"></span>';
  }).join('');

  return '<div class="actor-tile ' + sophCls + '" data-name="' + esc(a.name) + '" data-idx="' + idx + '">'
    + '<div class="actor-tile-header">'
    +   '<div><div class="actor-tile-name">' + esc(a.name) + '</div></div>'
    +   '<div style="text-align:right;flex-shrink:0">'
    +     '<div class="actor-tile-count">' + a.threat_count + '</div>'
    +     '<div class="actor-count-label">reports</div>'
    +   '</div>'
    + '</div>'
    + '<div class="actor-tile-tags">' + countryTag + motivTag + sophTag + '</div>'
    + aliases
    + '<div class="actor-tile-footer">'
    +   '<div class="actor-tile-sectors">' + (sectorBadges || '<span class="text-xs text-3">—</span>') + '</div>'
    +   '<div style="display:flex;align-items:center;gap:8px">'
    +     '<div class="actor-sev-row">' + sevDots + '</div>'
    +     '<span class="actor-last-seen">' + relTime(a.last_seen) + '</span>'
    +   '</div>'
    + '</div>'
    + '</div>';
}

function selectActor(actor) {
  _selected = actor.name;

  document.querySelectorAll('.actor-tile').forEach(function(t) { t.classList.remove('selected'); });
  const tile = document.querySelector('[data-name="' + CSS.escape(actor.name) + '"]');
  if (tile) tile.classList.add('selected');

  const el       = document.getElementById('actor-detail');
  const sophLabel = SOPH_LABEL[actor.sophistication] || actor.sophistication || 'Unknown';
  const motivColor = MOTIV_COLORS[actor.motivation] || '#4a5568';

  const aliasesHtml = actor.aliases && actor.aliases.length
    ? actor.aliases.map(function(a) {
        return '<span class="badge badge-unknown" style="font-size:.6rem;margin:2px">' + esc(a) + '</span>';
      }).join('')
    : '<span class="text-xs text-3">None recorded</span>';

  const recentThreats = (actor.recent_threats || []).map(function(t) {
    return '<div class="adp-threat-item">'
      + '<div>' + sevBadge(t.severity) + '</div>'
      + '<div style="flex:1;min-width:0">'
      +   '<div class="adp-threat-title"><a href="/threat-detail.html?id=' + t.id + '" style="color:var(--text)">' + esc(t.title) + '</a></div>'
      +   '<div class="adp-threat-meta">' + esc(t.source_name || '') + ' · ' + relTime(t.ingested_at) + '</div>'
      + '</div>'
      + '</div>';
  }).join('') || '<div class="text-xs text-3">No recent threats in selected window</div>';

  const sectorBadges = [...new Set(actor.sectors || [])].map(secBadge).join(' ') || '<span class="text-xs text-3">—</span>';

  el.innerHTML =
    '<div class="adp-header">'
    + '<div class="adp-name">' + esc(actor.name) + '</div>'
    + '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px">'
    +   (actor.origin_country ? '<span class="actor-tag country">' + esc(actor.origin_country) + '</span>' : '')
    +   '<span class="actor-tag motiv-' + (actor.motivation || 'unknown') + '">' + esc(actor.motivation || 'unknown') + '</span>'
    +   '<span class="actor-tag soph">' + esc(sophLabel) + '</span>'
    + '</div>'
    + '<div style="display:flex;gap:4px">' + sectorBadges + '</div>'
    + '</div>'

    + '<div class="adp-section">'
    + '<div class="adp-section-title">Intelligence Profile</div>'
    + '<div class="adp-meta-row"><span class="adp-meta-key">Reports seen</span><span class="adp-meta-val" style="color:var(--blue);font-size:.85rem;font-weight:700">' + actor.threat_count + '</span></div>'
    + '<div class="adp-meta-row"><span class="adp-meta-key">First observed</span><span class="adp-meta-val">' + (actor.active_since ? esc(actor.active_since) : (actor.first_seen ? fmtDate(actor.first_seen) : '—')) + '</span></div>'
    + '<div class="adp-meta-row"><span class="adp-meta-key">Last observed</span><span class="adp-meta-val">' + (actor.last_seen ? relTime(actor.last_seen) : '—') + '</span></div>'
    + '<div class="adp-meta-row"><span class="adp-meta-key">Motivation</span><span class="adp-meta-val" style="color:' + motivColor + ';text-transform:capitalize">' + esc(actor.motivation || '—') + '</span></div>'
    + '<div class="adp-meta-row"><span class="adp-meta-key">Sophistication</span><span class="adp-meta-val">' + esc(sophLabel) + '</span></div>'
    + '</div>'

    + (actor.description
      ? '<div class="adp-section"><div class="adp-section-title">Description</div><div class="adp-desc">' + esc(actor.description) + '</div></div>'
      : '')

    + '<div class="adp-section">'
    + '<div class="adp-section-title">Known Aliases</div>'
    + '<div style="display:flex;flex-wrap:wrap;gap:4px">' + aliasesHtml + '</div>'
    + '</div>'

    + '<div class="adp-section">'
    + '<div class="adp-section-title">Recent Threat Reports</div>'
    + recentThreats
    + (actor.threat_count > 5 ? '<div style="margin-top:8px"><a href="/threats.html" class="text-xs" style="color:var(--blue)">View all ' + actor.threat_count + ' reports →</a></div>' : '')
    + '</div>';
}

function renderCountryChart(byCountry) {
  const el = document.getElementById('country-chart');
  if (!byCountry.length) {
    el.innerHTML = '<div class="text-xs text-3">No origin country data yet</div>';
    return;
  }
  const max = byCountry[0]?.cnt || 1;
  el.innerHTML = byCountry.map(function(c) {
    return '<div class="country-bar">'
      + '<span class="country-bar-name">' + esc(c.origin_country || 'Unknown') + '</span>'
      + '<div class="country-bar-track"><div class="country-bar-fill" style="width:' + Math.round(c.cnt / max * 100) + '%"></div></div>'
      + '<span class="country-bar-cnt">' + c.cnt + '</span>'
      + '</div>';
  }).join('');
}

function renderMotivChart(byMotiv) {
  const el = document.getElementById('motiv-chart');
  if (!byMotiv.length) {
    el.innerHTML = '<div class="text-xs text-3">No motivation data yet</div>';
    return;
  }
  el.innerHTML = '<div class="motiv-list">' + byMotiv.map(function(m) {
    return '<div class="motiv-row">'
      + '<div class="motiv-dot" style="background:' + (MOTIV_COLORS[m.motivation] || '#4a5568') + '"></div>'
      + '<span class="motiv-name">' + esc(m.motivation || 'unknown') + '</span>'
      + '<span class="motiv-cnt">' + m.cnt + '</span>'
      + '</div>';
  }).join('') + '</div>';
}

function setDays(days, btn) {
  _days = days;
  document.querySelectorAll('.time-pill').forEach(function(b) { b.classList.remove('active'); });
  if (btn) btn.classList.add('active');
  loadActors();
}

function setMotiv(btn, val) {
  _motiv = val;
  btn.closest('.filter-group').querySelectorAll('.filter-pill').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
  renderGrid();
}

function setSoph(btn, val) {
  _soph = val;
  btn.closest('.filter-group').querySelectorAll('.filter-pill').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
  renderGrid();
}

let _st;
function searchActors(q) {
  clearTimeout(_st);
  _st = setTimeout(function() { _search = q; loadActors(); }, 300);
}

loadActors();
setInterval(loadActors, 60000);
connectSse(null, loadActors);
