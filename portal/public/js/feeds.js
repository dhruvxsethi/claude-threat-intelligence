async function loadFeeds() {
  const d=await fetch('/api/feeds').then(r=>r.json());
  const healthy=(d.health||[]).filter(f=>f.is_healthy).length;
  const failed=(d.health||[]).filter(f=>!f.is_healthy).length;
  setText('feeds-healthy',healthy);
  setText('feeds-failed',failed);
  setText('feeds-total',d.health?.length||0);
  const today=new Date().toDateString();
  setText('runs-today',(d.recentRuns||[]).filter(r=>new Date(r.started_at).toDateString()===today).length);
  renderHealth(d.health||[]);
  renderRuns(d.recentRuns||[]);
}

function setText(id,v){const el=document.getElementById(id);if(el)el.textContent=v;}

function renderHealth(feeds) {
  const el=document.getElementById('feed-health-list');
  if(!feeds.length){el.innerHTML='<div class="text-sm text-3" style="padding:12px">No feed data yet — run the pipeline first.</div>';return;}
  el.innerHTML=feeds.map(f=>`<div class="feed-row">
    <div class="feed-dot ${f.is_healthy?'ok':'err'}"></div>
    <span class="feed-name">${esc(f.feed_name||f.feed_id)}</span>
    <span class="feed-count">${f.total_threats_contributed||0} threats</span>
    <span class="text-xs text-3">${f.last_success?relTime(f.last_success):'never'}</span>
    ${!f.is_healthy?`<span class="badge badge-critical" style="font-size:.65rem">${f.consecutive_failures} fails</span>`:''}
  </div>`).join('');
}

function renderRuns(runs) {
  const el=document.getElementById('recent-runs');
  if(!runs.length){el.innerHTML='<div class="text-sm text-3" style="padding:12px">No runs yet.</div>';return;}
  el.innerHTML=`<div class="table-wrap"><table class="data-table"><thead><tr>
    <th>Feed</th><th>Slot</th><th>Status</th><th>Fetched</th><th>New</th><th>Analyzed</th><th>Threats</th><th>Started</th>
  </tr></thead><tbody>${runs.map(r=>`<tr>
    <td class="text-sm">${esc(r.feed_name||r.feed_id)}</td>
    <td><span class="badge badge-unknown">${r.slot||'?'}</span></td>
    <td><span class="badge badge-${r.status==='success'?'low':r.status==='failed'?'critical':r.status==='running'?'medium':'unknown'}">${r.status}</span></td>
    <td class="text-xs mono">${r.articles_fetched||0}</td>
    <td class="text-xs mono">${r.articles_new||0}</td>
    <td class="text-xs mono">${r.articles_analyzed||0}</td>
    <td class="text-xs mono" style="color:var(--low)">${r.threats_created||0}</td>
    <td class="text-xs text-3">${relTime(r.started_at)}</td>
  </tr>`).join('')}</tbody></table></div>`;
}

loadFeeds();
setInterval(loadFeeds,15000);
connectSse(null,loadFeeds);
