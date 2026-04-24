async function loadIocs() {
  const type=document.getElementById('f-ioc-type')?.value||'';
  const days=document.getElementById('f-ioc-days')?.value||'7';
  const conf=document.getElementById('f-ioc-confidence')?.value||'50';
  const search=document.getElementById('f-ioc-search')?.value||'';
  const p=new URLSearchParams({days,min_confidence:conf,limit:300});
  if(type) p.set('type',type);
  if(search) p.set('search',search);
  const d=await fetch(`/api/iocs?${p}`).then(r=>r.json());
  renderChips(d.type_counts||[]);
  renderIocs(d.iocs||[]);
}

function renderChips(tc) {
  const el=document.getElementById('ioc-chips'); if(!el) return;
  el.innerHTML=tc.map(t=>{
    const c=IOC_COLORS[t.ioc_type]||'#6b7280';
    return `<span onclick="document.getElementById('f-ioc-type').value='${t.ioc_type}';loadIocs()" style="padding:3px 12px;border-radius:99px;font-size:.72rem;cursor:pointer;background:${c}22;color:${c};border:1px solid ${c}44;font-weight:600">${t.ioc_type.replace(/_/g,' ')} <span style="opacity:.7">${t.cnt}</span></span>`;
  }).join('');
}

function renderIocs(iocs) {
  const el=document.getElementById('iocs-list');
  const cnt=document.getElementById('ioc-count');
  if(cnt) cnt.textContent=`${iocs.length} IOCs`;
  if(!iocs.length){
    el.innerHTML=`<div class="empty"><div class="empty-icon">🔍</div><div class="empty-title">No IOCs found</div><div class="empty-sub">Adjust filters or run the pipeline.</div></div>`;
    return;
  }
  el.innerHTML=iocs.map(i=>`<div class="ioc-row">
    ${iocPill(i.ioc_type)}
    <span class="ioc-val" title="${esc(i.ioc_value)}">${esc(i.ioc_value)}</span>
    ${i.malware_family?`<span class="text-xs" style="color:var(--medium);white-space:nowrap">${esc(i.malware_family)}</span>`:''}
    <a href="/threat-detail.html?id=${i.threat_id}" class="text-xs text-3" style="white-space:nowrap;max-width:160px;overflow:hidden;text-overflow:ellipsis">${esc((i.threat_title||'').slice(0,40))}</a>
    <span class="ioc-conf">${i.confidence}%</span>
    <button class="copy-btn" onclick="copyToClipboard('${i.ioc_value.replace(/'/g,"\\'")}')">⎘</button>
  </div>`).join('');
}

function exportIocs() {
  const type=document.getElementById('f-ioc-type')?.value||'';
  const days=document.getElementById('f-ioc-days')?.value||'7';
  const p=new URLSearchParams({days,min_confidence:0,limit:10000});
  if(type) p.set('type',type);
  fetch(`/api/iocs?${p}`).then(r=>r.json()).then(d=>{
    const csv='type,value,confidence,malware_family,context,threat_title,severity\n'+(d.iocs||[]).map(i=>`${i.ioc_type},"${i.ioc_value}",${i.confidence},"${i.malware_family||''}","${i.context||''}","${i.threat_title||''}",${i.severity}`).join('\n');
    const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'})); a.download=`iocs-${new Date().toISOString().slice(0,10)}.csv`; a.click();
    toast(`Exported ${d.iocs?.length||0} IOCs`,'success');
  });
}

loadIocs();
setInterval(loadIocs,60000);
