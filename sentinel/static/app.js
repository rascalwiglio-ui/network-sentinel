const state = {
  devices: [], listeners: [], connections: [], alerts: [], traffic: [],
  network: {}, overview: {}, status: {}, dns: [], communications: [],
  anomalies: [], baseline: {}, flows: [], timeline: [], incidents: [], capture: {}, fleet: {},
  deviceFilter: 'all', alertFilter: 'open', query: ''
};

const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const when = ts => ts ? new Date(ts * 1000).toLocaleString() : '—';
const shortWhen = ts => ts ? new Date(ts * 1000).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) : '—';

function fmtRate(bytesPerSecond){
  const units=['B/s','KB/s','MB/s','GB/s']; let v=Number(bytesPerSecond||0),i=0;
  while(v>=1024 && i<units.length-1){v/=1024;i++;}
  return `${v.toFixed(v>=100?0:v>=10?1:2)} ${units[i]}`;
}

function fmtBytes(bytes){
  const units=['B','KB','MB','GB','TB']; let v=Number(bytes||0),i=0;
  while(v>=1024 && i<units.length-1){v/=1024;i++;}
  return `${v.toFixed(v>=100?0:v>=10?1:2)} ${units[i]}`;
}

async function api(url, options){
  const res = await fetch(url, options);
  if(!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

function toast(message){
  const el=$('toast'); el.textContent=message; el.classList.add('show');
  clearTimeout(toast.timer); toast.timer=setTimeout(()=>el.classList.remove('show'),2200);
}

function scoreMeta(score){
  if(score>=90) return ['Calm','var(--green)'];
  if(score>=70) return ['Watch','var(--amber)'];
  return ['Needs attention','var(--red)'];
}

function renderOverview(){
  const o=state.overview, s=state.status;
  const score=Number(o.sentinel_score ?? 0), [label,color]=scoreMeta(score);
  $('scoreValue').textContent=score;
  $('scoreRing').style.setProperty('--score',score);
  $('scoreRing').style.background=`conic-gradient(${color} ${score}%, #1a2635 0)`;
  $('scoreLabel').textContent=label;

  $('devicesOnline').textContent=o.devices_online ?? '—';
  $('devicesMeta').textContent=`${o.devices_total ?? 0} known · ${o.devices_risky_online ?? 0} risk`;
  $('connectionsCount').textContent=o.connections ?? '—';
  $('listenersCount').textContent=o.listeners ?? '—';
  $('alertsCount').textContent=o.alerts_open ?? '—';
  $('alertsMeta').textContent=`${o.alerts_high ?? 0} high · ${o.alerts_medium ?? 0} medium`;
  $('anomaliesCount').textContent=o.anomalies_open ?? '—';
  $('domainsCount').textContent=o.known_domains ?? '—';
  $('incidentsCount').textContent=o.incidents_open ?? '—';
  const cap=state.capture||{};
  $('captureState').textContent=cap.running?'LIVE':cap.configured?'WAIT':'OFF';
  $('captureMeta').textContent=cap.running?`${fmtBytes(cap.bytes)} observed`:cap.configured?'sensor unavailable':'optional sensor';
  $('baselineMeta').textContent=state.baseline.ready?'baseline ready':'learning baseline';
  $('rxRate').textContent=fmtRate(o.rx_bps);
  $('txRate').textContent=fmtRate(o.tx_bps);
  $('lastScan').textContent=when(s.last_scan);
  $('lastDiscovery').textContent=when(s.last_discovery);

  const online=Boolean(s.running), discovering=Boolean(s.discovery_running);
  $('sideDot').className=`status-dot ${online?'online':''}`;
  $('sideStatus').textContent=discovering?'Discovering LAN':online?'Engine online':'Engine offline';
  $('enginePill').className=`pill ${online?'good':'bad'}`;
  $('enginePill').textContent=discovering?'discovering':online?'online':'offline';
}

function renderBaseline(){
  const b=state.baseline || {}, counts=b.counts || {};
  const ready=Boolean(b.ready), warmup=Number(b.warmup_seconds || 1), remaining=Number(b.remaining_seconds || 0);
  const elapsed=Math.max(0,warmup-remaining), progress=ready?100:Math.min(100,Math.round(elapsed/warmup*100));
  $('baselinePill').className=`pill ${ready?'good':'warn'}`;
  $('baselinePill').textContent=ready?'ready':'learning';
  $('baselineProgress').style.width=`${progress}%`;
  $('baselineStatusText').textContent=ready
    ? `Baseline active · ${b.history_retention_days ?? 7} day history retention`
    : `Learning normal activity · ${remaining}s remaining`;
  $('knownProcesses').textContent=counts.processes ?? 0;
  $('knownEndpoints').textContent=counts.endpoints ?? 0;
  $('knownDomains').textContent=counts.domains ?? 0;
  $('knownFlows').textContent=counts.flows ?? 0;

  const supported=b.dns_supported;
  $('dnsPill').className=`pill ${supported===true?'good':supported===false?'warn':'neutral'}`;
  $('dnsPill').textContent=supported===true?'monitoring':supported===false?'limited':'checking';
  $('dnsPill').title=b.dns_error || '';
}

function renderAnomalies(){
  const open=state.anomalies.filter(a=>!a.acknowledged);
  $('anomalyBadge').className=`pill ${open.length?'warn':'good'}`;
  $('anomalyBadge').textContent=`${open.length} open`;
  const rows=state.anomalies.slice(0,8);
  $('anomalyFeed').innerHTML=rows.length?rows.map(a=>`
    <div class="anomaly-item ${a.acknowledged?'acknowledged':''}">
      <div class="anomaly-icon ${esc(a.severity)}">${a.severity==='high'?'!':'⌁'}</div>
      <div class="anomaly-copy"><strong>${esc(a.title)}</strong><span>${esc(a.details)}</span></div>
      <div class="anomaly-time">${shortWhen(a.created_at)}</div>
    </div>`).join(''):`<div class="empty">No behavior anomalies observed</div>`;
}

function renderDns(){
  const rows=state.dns.filter(d=>matchesQuery(d.domain,d.record_type,d.data));
  $('dnsTable').innerHTML=rows.length?rows.slice(0,200).map(d=>`<tr>
    <td><span class="domain-name">${esc(d.domain)}</span></td>
    <td>${esc(d.record_type)}</td>
    <td class="truncate-cell" title="${esc(d.data)}">${esc(d.data||'—')}</td>
    <td>${esc(d.seen_count)}</td>
    <td>${when(d.last_seen)}</td>
  </tr>`).join(''):`<tr><td colspan="5"><div class="empty">No DNS records in this view</div></td></tr>`;
}

function renderCommunications(){
  const rows=state.communications.filter(c=>matchesQuery(c.process,c.proto,c.remote_ip,c.remote_port));
  $('commBadge').textContent=`${state.communications.length} learned`;
  $('communicationsTable').innerHTML=rows.length?rows.slice(0,250).map(c=>`<tr>
    <td><span class="device-name">${esc(c.process)}</span></td>
    <td>${esc(String(c.proto).toUpperCase())}</td>
    <td>${esc(c.remote_ip)}:${esc(c.remote_port)}</td>
    <td>${esc(c.seen_count)}</td>
    <td>${when(c.last_seen)}</td>
  </tr>`).join(''):`<tr><td colspan="5"><div class="empty">No learned external endpoints</div></td></tr>`;
}

function renderCapture(){
  const c=state.capture||{};
  const active=Boolean(c.running), configured=Boolean(c.configured);
  $('capturePill').className=`pill ${active?'good':configured?'warn':'neutral'}`;
  $('capturePill').textContent=active?'live':configured?'waiting':'disabled';
  $('capturePackets').textContent=Number(c.packets||0).toLocaleString();
  $('captureBytes').textContent=fmtBytes(c.bytes||0);
  $('captureDns').textContent=Number(c.dns_events||0).toLocaleString();
  $('capturePulse').className=active?'capture-live':'';
  $('captureTitle').textContent=active?'Metadata sensor active':configured?'Capture configured but unavailable':'Capture is optional';
  $('captureDescription').textContent=active
    ? 'Only packet metadata is aggregated; payload bytes are not stored.'
    : (c.error || 'Use scripts/enable-capture.cmd, install Npcap on Windows, then run scripts/run-capture.cmd.');
}

function renderIncidents(){
  const rows=state.incidents.filter(i=>matchesQuery(i.title,i.summary,i.process,i.remote_ip,i.domain,i.severity));
  const open=state.incidents.filter(i=>i.status==='open');
  $('incidentBadge').className=`pill ${open.length?'warn':'good'}`;
  $('incidentBadge').textContent=`${open.length} open`;
  $('incidentFeed').innerHTML=rows.length?rows.slice(0,18).map(i=>`
    <div class="incident-item ${esc(i.severity)} ${i.status==='closed'?'closed':''}">
      <div class="incident-score"><b>${esc(i.score)}</b><span>${esc(i.severity)}</span></div>
      <div class="incident-copy"><strong>${esc(i.title)}</strong><span>${esc(i.summary)}</span>
        <small>${esc(i.process||i.remote_ip||i.domain||'correlated local telemetry')} · ${when(i.updated_at)}</small></div>
      <div class="incident-actions">${i.status==='open'?`<button class="ack-btn" onclick="closeIncident(${i.id})">close</button>`:'closed'}</div>
    </div>`).join(''):`<div class="empty">No correlated incidents</div>`;
}

function renderFlows(){
  const rows=state.flows.filter(f=>matchesQuery(f.process,f.proto,f.direction,f.local_ip,f.remote_ip,f.local_port,f.remote_port));
  $('flowBadge').textContent=`${state.flows.length} flows`;
  $('flowsTable').innerHTML=rows.length?rows.slice(0,300).map(f=>`<tr>
    <td><span class="flow-direction ${esc(f.direction)}">${esc(f.direction)}</span></td>
    <td><span class="device-name">${esc(f.process||'unknown')}</span><span class="subline">${f.pid?`PID ${f.pid}`:''}</span></td>
    <td>${esc(String(f.proto).toUpperCase())}</td>
    <td>${esc(f.remote_ip)}:${esc(f.remote_port||'')}</td>
    <td>${Number(f.packets||0).toLocaleString()}</td>
    <td>${fmtBytes(f.bytes||0)}</td>
  </tr>`).join(''):`<tr><td colspan="6"><div class="empty">No packet-derived flows yet. Core socket monitoring is still active.</div></td></tr>`;
}

function renderTimeline(){
  const rows=state.timeline.filter(e=>matchesQuery(e.category,e.severity,e.title,e.details,e.process,e.remote_ip,e.domain));
  $('timelineBadge').textContent=`${rows.length} events`;
  $('timelineFeed').innerHTML=rows.length?rows.slice(0,70).map(e=>`
    <div class="timeline-item">
      <div class="timeline-dot ${esc(e.category)} ${esc(e.severity)}"></div>
      <div class="timeline-copy"><strong>${esc(e.title)}</strong><span>${esc(e.details)}</span>
        <small>${esc(e.category)}${e.process?` · ${esc(e.process)}`:''}${e.remote_ip?` · ${esc(e.remote_ip)}`:''}</small></div>
      <time>${shortWhen(e.created_at)}</time>
    </div>`).join(''):`<div class="empty">No timeline events</div>`;
}

function renderNetworkInfo(){
  const n=state.network, s=state.status;
  if(!n || !n.cidr){
    $('networkInfo').innerHTML=`<div class="empty">${esc(s.discovery_error || 'Waiting for discovery...')}</div>`;
    return;
  }
  const rows=[
    ['Interface',n.interface],['Local IP',n.local_ip],['Local MAC',n.local_mac||'unknown'],
    ['Subnet',n.cidr],['Gateway',n.gateway||'unknown'],['Discovery',s.active_discovery?'active':'passive'],
    ['DNS telemetry',s.dns_supported===true?'available':s.dns_supported===false?'limited':'checking'],
    ['Last discovery',when(s.last_discovery)]
  ];
  $('networkInfo').innerHTML=rows.map(([k,v])=>`<div class="kv-row"><div class="kv-key">${esc(k)}</div><div class="kv-val">${esc(v)}</div></div>`).join('');
}

function addSvg(tag, attrs={}, text=''){
  const el=document.createElementNS('http://www.w3.org/2000/svg',tag);
  Object.entries(attrs).forEach(([k,v])=>el.setAttribute(k,v));
  if(text) el.textContent=text;
  return el;
}

function renderTopology(){
  const svg=$('networkMap'); svg.innerHTML='';
  const devices=state.devices.filter(d=>d.online), n=state.network||{};
  $('mapSummary').textContent=`${devices.length} online · ${state.devices.length} known`;
  if(!devices.length){
    svg.appendChild(addSvg('text',{x:460,y:215,'text-anchor':'middle',class:'node-sub'},'No online devices discovered yet'));
    return;
  }
  const center=devices.find(d=>d.is_gateway)||devices.find(d=>d.ip===n.local_ip)||devices[0];
  const sats=devices.filter(d=>d.ip!==center.ip).slice(0,34), cx=460,cy=215;
  sats.forEach((d,i)=>{
    const angle=(Math.PI*2*i/Math.max(sats.length,1))-Math.PI/2;
    const ring=sats.length>18 && i%2 ? .72 : 1;
    const x=cx+Math.cos(angle)*350*ring, y=cy+Math.sin(angle)*155*ring;
    svg.appendChild(addSvg('line',{x1:cx,y1:cy,x2:x,y2:y,class:'link'}));
    drawNode(svg,x,y,d,n.local_ip,false);
  });
  drawNode(svg,cx,cy,center,n.local_ip,true);
}

function drawNode(svg,x,y,d,localIp,large){
  const g=addSvg('g');
  let cls='node-circle';
  if(d.is_gateway) cls+=' node-gateway'; else if(d.ip===localIp) cls+=' node-local'; else if(!d.online) cls+=' node-offline';
  if(d.trusted) cls+=' node-trusted';
  if((d.risk?.score||0)>=60) cls+=' node-risk-high'; else if((d.risk?.score||0)>=30) cls+=' node-risk-medium';
  g.appendChild(addSvg('circle',{cx:x,cy:y,r:large?24:15,class:cls}));
  const reasons=(d.risk?.reasons||[]).join(', ');
  g.appendChild(addSvg('title',{},`${d.hostname||d.ip}\n${d.ip}\n${d.vendor||'Unknown vendor'}\nRisk ${d.risk?.score ?? 0}/100\n${reasons}`));
  g.appendChild(addSvg('text',{x,y:y+(large?39:30),'text-anchor':'middle',class:'node-label'},(d.hostname||d.ip).slice(0,25)));
  g.appendChild(addSvg('text',{x,y:y+(large?51:41),'text-anchor':'middle',class:'node-sub'},d.hostname?`${d.ip} · R${d.risk?.score ?? 0}`:(d.is_gateway?'gateway':'')));
  svg.appendChild(g);
}

function drawTraffic(){
  const canvas=$('trafficChart'), rect=canvas.getBoundingClientRect(), ratio=window.devicePixelRatio||1;
  canvas.width=Math.max(1,Math.floor(rect.width*ratio)); canvas.height=Math.max(1,Math.floor(rect.height*ratio));
  const ctx=canvas.getContext('2d'); ctx.setTransform(ratio,0,0,ratio,0,0);
  const w=rect.width,h=rect.height,pad=28,points=state.traffic.slice(-180); ctx.clearRect(0,0,w,h);
  if(points.length<2) return;
  const max=Math.max(1024,...points.map(p=>Math.max(p.rx_bps,p.tx_bps)));
  ctx.strokeStyle='#1b2a3b';ctx.lineWidth=1;
  for(let i=0;i<4;i++){const y=pad+(h-pad*2)*(i/3);ctx.beginPath();ctx.moveTo(pad,y);ctx.lineTo(w-pad,y);ctx.stroke();}
  function series(key,color,fill){
    const coords=points.map((p,i)=>[pad+(w-pad*2)*(i/Math.max(points.length-1,1)),h-pad-(h-pad*2)*(p[key]/max)]);
    ctx.beginPath();coords.forEach(([x,y],i)=>i?ctx.lineTo(x,y):ctx.moveTo(x,y));ctx.strokeStyle=color;ctx.lineWidth=1.8;ctx.stroke();
    if(fill){ctx.lineTo(coords.at(-1)[0],h-pad);ctx.lineTo(coords[0][0],h-pad);ctx.closePath();const grad=ctx.createLinearGradient(0,pad,0,h-pad);grad.addColorStop(0,fill);grad.addColorStop(1,'rgba(0,0,0,0)');ctx.fillStyle=grad;ctx.fill();}
  }
  series('rx_bps','#53d6e8','rgba(83,214,232,.08)'); series('tx_bps','#f3ba55',null);
  ctx.fillStyle='#74869e';ctx.font='10px system-ui';ctx.fillText(`peak ${fmtRate(max)}`,pad,15);
}

function matchesQuery(...parts){
  if(!state.query) return true;
  return parts.some(v=>String(v??'').toLowerCase().includes(state.query));
}

function riskBadge(risk){
  const r=risk||{score:0,level:'low',reasons:[]};
  const title=(r.reasons||[]).join(' · ');
  return `<span class="risk-badge ${esc(r.level)}" title="${esc(title)}"><b>${esc(r.score)}</b><span>${esc(r.level)}</span></span>`;
}

function probeMeta(device){
  if(!device.monitored) return ['pending','neutral'];
  if(device.probe_online) return ['reachable','good'];
  return ['unreachable','warn'];
}

function renderFleet(){
  const f=state.fleet||{};
  $('fleetKnown').textContent=f.known ?? 0;
  $('fleetMonitored').textContent=f.monitored ?? 0;
  $('fleetReachable').textContent=f.reachable ?? 0;
  $('fleetUnreachable').textContent=f.unreachable ?? 0;
  $('fleetServices').textContent=f.active_services ?? 0;
  $('fleetTrafficSeen').textContent=f.traffic_seen_recently ?? 0;

  const status=$('fleetStatus');
  if(f.error){status.className='pill bad';status.textContent='error';status.title=f.error;}
  else if(!f.enabled){status.className='pill neutral';status.textContent='disabled';}
  else if(f.running){status.className='pill warn';status.textContent='probing';}
  else {status.className='pill good';status.textContent=f.last_scan?'active':'starting';}

  const rows=state.devices.filter(d=>matchesQuery(d.ip,d.mac,d.hostname,d.vendor,d.risk?.reasons?.join(' ')));
  $('fleetTable').innerHTML=rows.length?rows.map(d=>{
    const [label,cls]=probeMeta(d);
    const t=d.traffic||{};
    const traffic=Number(t.bytes_from||0)+Number(t.bytes_to||0);
    return `<tr>
      <td><span class="device-name">${esc(d.hostname||(d.is_gateway?'Gateway':'Unknown device'))}</span><span class="subline">${esc(d.ip)} · ${esc(d.vendor||'unknown vendor')}</span></td>
      <td><span class="pill ${cls}">${label}</span></td>
      <td>${d.probe_latency_ms==null?'—':`${Number(d.probe_latency_ms).toFixed(1)} ms`}</td>
      <td><span class="service-count">${Number(d.open_service_count||0)}</span></td>
      <td>${traffic?fmtBytes(traffic):'—'}<span class="subline">${t.last_seen?when(t.last_seen):'sensor has not seen traffic'}</span></td>
      <td>${when(d.last_probe)}</td>
      <td class="row-actions"><button class="ack-btn" onclick="probeDevice('${encodeURIComponent(d.ip)}')">probe</button><button class="ack-btn" onclick="openDeviceDrawer('${encodeURIComponent(d.ip)}')">inspect</button></td>
    </tr>`;
  }).join(''):`<tr><td colspan="7"><div class="empty">No discovered devices yet</div></td></tr>`;
}

async function openDeviceDrawer(encodedIp){
  const ip=decodeURIComponent(encodedIp);
  const drawer=$('deviceDrawer'), backdrop=$('deviceDrawerBackdrop');
  drawer.classList.add('open');backdrop.classList.add('open');drawer.setAttribute('aria-hidden','false');
  $('drawerTitle').textContent=ip;$('drawerSubtitle').textContent='Loading device profile...';
  $('drawerBody').innerHTML='<div class="empty">Loading telemetry...</div>';
  try{
    const [profile,history]=await Promise.all([
      api(`/api/devices/${encodeURIComponent(ip)}/profile`),
      api(`/api/devices/${encodeURIComponent(ip)}/history?limit=40`)
    ]);
    const services=profile.services||[], active=services.filter(x=>x.active);
    const traffic=profile.traffic||{};
    const risk=profile.risk||{score:0,level:'low',reasons:[]};
    $('drawerTitle').textContent=profile.hostname || (profile.is_gateway?'Gateway':'Unknown device');
    $('drawerSubtitle').textContent=`${profile.ip} · ${profile.mac||'MAC unknown'} · ${profile.vendor||'vendor unknown'}`;
    const reasons=(risk.reasons||[]).map(x=>`<li>${esc(x)}</li>`).join('') || '<li>No notable local heuristic factors</li>';
    const serviceHtml=active.length?active.map(x=>`<span class="service-chip">${esc(x.service)} <b>${esc(x.port)}</b></span>`).join(''):'<span class="muted">No monitored TCP services currently open</span>';
    const historyHtml=history.length?history.slice(0,18).map(h=>`<div class="history-row"><span class="dot ${h.online?'online':''}"></span><span>${h.online?'reachable':'unreachable'}</span><b>${h.latency_ms==null?'—':`${Number(h.latency_ms).toFixed(1)} ms`}</b><time>${when(h.observed_at)}</time></div>`).join(''):'<div class="empty">No probe history yet</div>';
    $('drawerBody').innerHTML=`
      <div class="drawer-grid">
        <div class="drawer-stat"><span>Risk</span><strong class="risk-text ${esc(risk.level)}">${esc(risk.score)}/100</strong></div>
        <div class="drawer-stat"><span>Probe</span><strong>${profile.monitored?(profile.probe_online?'reachable':'unreachable'):'pending'}</strong></div>
        <div class="drawer-stat"><span>Latency</span><strong>${profile.probe_latency_ms==null?'—':`${Number(profile.probe_latency_ms).toFixed(1)} ms`}</strong></div>
        <div class="drawer-stat"><span>Services</span><strong>${active.length}</strong></div>
      </div>
      <div class="drawer-section"><h3>Exposed LAN services</h3><div class="service-list">${serviceHtml}</div></div>
      <div class="drawer-section"><h3>Sensor-observed traffic</h3>
        <div class="traffic-pairs"><div><span>From device</span><strong>${fmtBytes(traffic.bytes_from||0)}</strong><small>${Number(traffic.packets_from||0).toLocaleString()} packets</small></div><div><span>To device</span><strong>${fmtBytes(traffic.bytes_to||0)}</strong><small>${Number(traffic.packets_to||0).toLocaleString()} packets</small></div></div>
        <p class="drawer-note">These counters only include frames visible to the optional capture sensor. They are not guaranteed to represent all traffic on a switched LAN.</p>
      </div>
      <div class="drawer-section"><h3>Risk factors</h3><ul class="reason-list">${reasons}</ul></div>
      <div class="drawer-section"><h3>Reachability history</h3><div class="history-list">${historyHtml}</div></div>
      <div class="drawer-actions"><button class="btn btn-primary" onclick="probeDevice('${encodeURIComponent(ip)}')">Probe now</button><button class="btn btn-ghost" onclick="setTrust('${encodeURIComponent(ip)}',${!profile.trusted})">${profile.trusted?'Remove trust':'Mark trusted'}</button></div>`;
  }catch(e){$('drawerBody').innerHTML=`<div class="empty">Unable to load device: ${esc(e.message)}</div>`;}
}

function closeDeviceDrawer(){
  $('deviceDrawer').classList.remove('open');$('deviceDrawerBackdrop').classList.remove('open');$('deviceDrawer').setAttribute('aria-hidden','true');
}

async function probeDevice(encodedIp){
  const ip=decodeURIComponent(encodedIp);
  try{await api(`/api/devices/${encodeURIComponent(ip)}/probe`,{method:'POST'});toast(`Probe queued for ${ip}`);}
  catch(e){toast(`Probe failed: ${e.message}`);}
}

async function fleetScan(){
  const btn=$('fleetScanBtn');btn.disabled=true;btn.textContent='Probe queued...';
  try{await api('/api/fleet/scan',{method:'POST'});toast('Fleet probe queued');}
  catch(e){toast(e.message);}finally{setTimeout(()=>{btn.disabled=false;btn.textContent='Probe all devices';},2200);}
}

function renderDevices(){
  let rows=state.devices.filter(d=>matchesQuery(d.ip,d.mac,d.hostname,d.vendor,d.risk?.reasons?.join(' ')));
  if(state.deviceFilter==='online') rows=rows.filter(d=>d.online);
  if(state.deviceFilter==='untrusted') rows=rows.filter(d=>d.online&&!d.trusted&&!d.is_gateway);
  if(state.deviceFilter==='risk') rows=rows.filter(d=>(d.risk?.score||0)>=30);
  $('devicesTable').innerHTML=rows.length?rows.map(d=>{
    const [probeLabel,probeClass]=probeMeta(d);
    return `<tr>
      <td><span class="device-status"><span class="dot ${d.online?'online':''}"></span>${d.online?'Online':'Offline'}</span></td>
      <td><span class="device-name">${esc(d.hostname || (d.is_gateway?'Gateway':'Unknown device'))}</span><span class="subline">${d.is_gateway?'default gateway':esc(d.interface||'')}</span></td>
      <td>${esc(d.ip)}</td><td>${esc(d.mac||'—')}</td><td>${esc(d.vendor||'—')}</td>
      <td>${riskBadge(d.risk)}</td>
      <td><span class="pill ${probeClass}">${probeLabel}</span><span class="subline">${d.probe_latency_ms==null?'':`${Number(d.probe_latency_ms).toFixed(1)} ms`}</span></td>
      <td>${Number(d.open_service_count||0)}</td>
      <td><button class="trust-btn ${d.trusted?'trusted':''}" onclick="setTrust('${encodeURIComponent(d.ip)}',${!d.trusted})">${d.trusted?'Trusted':'Mark trusted'}</button></td>
      <td>${when(d.last_seen)}</td>
      <td><button class="ack-btn" onclick="openDeviceDrawer('${encodeURIComponent(d.ip)}')">inspect</button></td>
    </tr>`;
  }).join(''):`<tr><td colspan="11"><div class="empty">No matching devices</div></td></tr>`;
}

function renderSockets(){
  const listeners=state.listeners.filter(x=>matchesQuery(x.proto,x.ip,x.port,x.process));
  const conns=state.connections.filter(x=>matchesQuery(x.proto,x.local?.ip,x.local?.port,x.remote?.ip,x.remote?.port,x.status,x.process)).slice(0,300);
  $('listenerBadge').textContent=listeners.length; $('connectionBadge').textContent=conns.length;
  $('listenersTable').innerHTML=listeners.length?listeners.map(x=>`<tr><td>${esc(x.proto.toUpperCase())}</td><td>${esc(x.ip)}</td><td>${esc(x.port)}</td><td>${esc(x.process||'—')}<span class="subline">${x.pid?`PID ${x.pid}`:''}</span></td></tr>`).join(''):`<tr><td colspan="4"><div class="empty">No listeners</div></td></tr>`;
  $('connectionsTable').innerHTML=conns.length?conns.map(x=>`<tr><td>${esc(x.proto.toUpperCase())}</td><td>${esc((x.local?.ip||'')+(x.local?.port?':'+x.local.port:''))}</td><td>${esc((x.remote?.ip||'')+(x.remote?.port?':'+x.remote.port:''))}</td><td>${esc(x.status||'—')}</td><td>${esc(x.process||'—')}</td></tr>`).join(''):`<tr><td colspan="5"><div class="empty">No matching connections</div></td></tr>`;
}

function visibleAlerts(){
  let rows=state.alerts.filter(a=>matchesQuery(a.title,a.details,a.kind,a.severity));
  if(state.alertFilter==='open') rows=rows.filter(a=>!a.acknowledged);
  if(state.alertFilter==='high') rows=rows.filter(a=>a.severity==='high'&&!a.acknowledged);
  if(state.alertFilter==='anomaly') rows=rows.filter(a=>String(a.kind||'').startsWith('anomaly_'));
  return rows;
}

function renderAlerts(){
  const rows=visibleAlerts();
  $('alertsTable').innerHTML=rows.length?rows.map(a=>`<tr style="${a.acknowledged?'opacity:.46':''}"><td><span class="severity ${esc(a.severity)}">${esc(a.severity)}</span></td><td><span class="device-name">${esc(a.title)}</span><span class="subline">${esc(a.kind)}</span></td><td>${esc(a.details)}</td><td>${when(a.created_at)}</td><td>${a.acknowledged?'✓':`<button class="ack-btn" onclick="ack(${a.id})">ack</button>`}</td></tr>`).join(''):`<tr><td colspan="5"><div class="empty">No alerts in this view</div></td></tr>`;
  const feed=state.alerts.filter(a=>!a.acknowledged).slice(0,7);
  $('activityFeed').innerHTML=feed.length?feed.map(a=>`<div class="activity-item"><div class="activity-bar ${esc(a.severity)}"></div><div><div class="activity-title">${esc(a.title)}</div><div class="activity-detail">${esc(a.details)}</div></div><div class="activity-time">${shortWhen(a.created_at)}</div></div>`).join(''):`<div class="empty">No open alerts</div>`;
}

async function setTrust(encodedIp,trusted){
  const ip=decodeURIComponent(encodedIp);
  try{await api(`/api/devices/${encodeURIComponent(ip)}/trust?trusted=${trusted}`,{method:'POST'});toast(trusted?'Device marked trusted':'Trust removed');await refresh();}
  catch(e){toast(`Unable to update trust: ${e.message}`);}
}

async function closeIncident(id){try{await api(`/api/incidents/${id}/close`,{method:'POST'});toast('Incident closed');await refresh();}catch(e){toast(e.message);}}

async function ack(id){try{await api(`/api/alerts/${id}/ack`,{method:'POST'});await refresh();}catch(e){toast(e.message);}}
async function ackAll(){try{const r=await api('/api/alerts/ack-all',{method:'POST'});toast(`${r.acknowledged} alerts acknowledged`);await refresh();}catch(e){toast(e.message);}}
async function scanNow(){
  const btn=$('scanBtn');btn.disabled=true;btn.textContent='Scan queued...';
  try{await api('/api/discovery/scan',{method:'POST'});toast('LAN discovery queued');}
  catch(e){toast(e.message);}finally{setTimeout(()=>{btn.disabled=false;btn.textContent='Scan network';},2500);}
}

function renderAll(){
  renderOverview();renderBaseline();renderAnomalies();renderDns();renderCommunications();
  renderCapture();renderIncidents();renderFlows();renderTimeline();
  renderNetworkInfo();renderTopology();drawTraffic();renderFleet();renderDevices();renderSockets();renderAlerts();
}

async function refresh(){
  try{
    const [status,overview,network,devices,listeners,connections,alerts,traffic,dns,communications,anomalies,baseline,flows,timeline,incidents,capture,fleet]=await Promise.all([
      api('/api/status'),api('/api/overview'),api('/api/network'),api('/api/devices'),api('/api/listeners'),api('/api/connections'),api('/api/alerts'),api('/api/traffic'),
      api('/api/dns?limit=250'),api('/api/communications?limit=300'),api('/api/anomalies?limit=100'),api('/api/baseline'),
      api('/api/flows?limit=300'),api('/api/timeline?limit=250'),api('/api/incidents?limit=100'),api('/api/capture'),api('/api/fleet')
    ]);
    Object.assign(state,{status,overview,network,devices,listeners,connections,alerts,traffic,dns,communications,anomalies,baseline,flows,timeline,incidents,capture,fleet});renderAll();
  }catch(e){$('sideStatus').textContent='API unavailable';$('sideDot').className='status-dot';console.error(e);}
}

$('scanBtn').addEventListener('click',scanNow);$('fleetScanBtn').addEventListener('click',fleetScan);$('ackAllBtn').addEventListener('click',ackAll);
$('globalSearch').addEventListener('input',e=>{state.query=e.target.value.trim().toLowerCase();renderFleet();renderDevices();renderSockets();renderAlerts();renderDns();renderCommunications();renderIncidents();renderFlows();renderTimeline();});
document.querySelectorAll('[data-device-filter]').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('[data-device-filter]').forEach(x=>x.classList.remove('active'));b.classList.add('active');state.deviceFilter=b.dataset.deviceFilter;renderDevices();}));
document.querySelectorAll('[data-alert-filter]').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('[data-alert-filter]').forEach(x=>x.classList.remove('active'));b.classList.add('active');state.alertFilter=b.dataset.alertFilter;renderAlerts();}));
document.querySelectorAll('.nav-link').forEach(a=>a.addEventListener('click',()=>{document.querySelectorAll('.nav-link').forEach(x=>x.classList.remove('active'));a.classList.add('active');}));
window.addEventListener('resize',drawTraffic);document.addEventListener('keydown',e=>{if(e.key==='Escape')closeDeviceDrawer();});

refresh();setInterval(refresh,3000);
