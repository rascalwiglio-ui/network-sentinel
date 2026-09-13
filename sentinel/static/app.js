const state = {
  devices: [], listeners: [], connections: [], alerts: [], traffic: [], network: {}, overview: {}, status: {},
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
  $('devicesMeta').textContent=`${o.devices_total ?? 0} known · ${o.devices_untrusted_online ?? 0} need trust`;
  $('connectionsCount').textContent=o.connections ?? '—';
  $('listenersCount').textContent=o.listeners ?? '—';
  $('alertsCount').textContent=o.alerts_open ?? '—';
  $('alertsMeta').textContent=`${o.alerts_high ?? 0} high · ${o.alerts_medium ?? 0} medium`;
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

function renderNetworkInfo(){
  const n=state.network, s=state.status;
  if(!n || !n.cidr){
    $('networkInfo').innerHTML=`<div class="empty">${esc(s.discovery_error || 'Waiting for discovery...')}</div>`;
    return;
  }
  const rows=[
    ['Interface',n.interface],['Local IP',n.local_ip],['Local MAC',n.local_mac||'unknown'],
    ['Subnet',n.cidr],['Gateway',n.gateway||'unknown'],['Discovery',s.active_discovery?'active':'passive'],
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
  g.appendChild(addSvg('circle',{cx:x,cy:y,r:large?24:15,class:cls}));
  const title=addSvg('title',{},`${d.hostname||d.ip}\n${d.ip}\n${d.vendor||'Unknown vendor'}\n${d.trusted?'Trusted':'Not trusted yet'}`); g.appendChild(title);
  g.appendChild(addSvg('text',{x,y:y+(large?39:30),'text-anchor':'middle',class:'node-label'},(d.hostname||d.ip).slice(0,25)));
  g.appendChild(addSvg('text',{x,y:y+(large?51:41),'text-anchor':'middle',class:'node-sub'},d.hostname?d.ip:(d.is_gateway?'gateway':'')));
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

function renderDevices(){
  let rows=state.devices.filter(d=>matchesQuery(d.ip,d.mac,d.hostname,d.vendor));
  if(state.deviceFilter==='online') rows=rows.filter(d=>d.online);
  if(state.deviceFilter==='untrusted') rows=rows.filter(d=>d.online&&!d.trusted&&!d.is_gateway);
  $('devicesTable').innerHTML=rows.length?rows.map(d=>`<tr>
    <td><span class="device-status"><span class="dot ${d.online?'online':''}"></span>${d.online?'Online':'Offline'}</span></td>
    <td><span class="device-name">${esc(d.hostname || (d.is_gateway?'Gateway':'Unknown device'))}</span><span class="subline">${d.is_gateway?'default gateway':esc(d.interface||'')}</span></td>
    <td>${esc(d.ip)}</td><td>${esc(d.mac||'—')}</td><td>${esc(d.vendor||'—')}</td>
    <td><button class="trust-btn ${d.trusted?'trusted':''}" onclick="setTrust('${encodeURIComponent(d.ip)}',${!d.trusted})">${d.trusted?'Trusted':'Mark trusted'}</button></td>
    <td>${when(d.last_seen)}</td></tr>`).join(''):`<tr><td colspan="7"><div class="empty">No matching devices</div></td></tr>`;
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

async function ack(id){try{await api(`/api/alerts/${id}/ack`,{method:'POST'});await refresh();}catch(e){toast(e.message);}}
async function ackAll(){try{const r=await api('/api/alerts/ack-all',{method:'POST'});toast(`${r.acknowledged} alerts acknowledged`);await refresh();}catch(e){toast(e.message);}}
async function scanNow(){
  const btn=$('scanBtn');btn.disabled=true;btn.textContent='Scan queued...';
  try{await api('/api/discovery/scan',{method:'POST'});toast('LAN discovery queued');}
  catch(e){toast(e.message);}finally{setTimeout(()=>{btn.disabled=false;btn.textContent='Scan network';},2500);}
}

function renderAll(){renderOverview();renderNetworkInfo();renderTopology();drawTraffic();renderDevices();renderSockets();renderAlerts();}

async function refresh(){
  try{
    const [status,overview,network,devices,listeners,connections,alerts,traffic]=await Promise.all([
      api('/api/status'),api('/api/overview'),api('/api/network'),api('/api/devices'),api('/api/listeners'),api('/api/connections'),api('/api/alerts'),api('/api/traffic')
    ]);
    Object.assign(state,{status,overview,network,devices,listeners,connections,alerts,traffic});renderAll();
  }catch(e){$('sideStatus').textContent='API unavailable';$('sideDot').className='status-dot';console.error(e);}
}

$('scanBtn').addEventListener('click',scanNow);$('ackAllBtn').addEventListener('click',ackAll);
$('globalSearch').addEventListener('input',e=>{state.query=e.target.value.trim().toLowerCase();renderDevices();renderSockets();renderAlerts();});
document.querySelectorAll('[data-device-filter]').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('[data-device-filter]').forEach(x=>x.classList.remove('active'));b.classList.add('active');state.deviceFilter=b.dataset.deviceFilter;renderDevices();}));
document.querySelectorAll('[data-alert-filter]').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('[data-alert-filter]').forEach(x=>x.classList.remove('active'));b.classList.add('active');state.alertFilter=b.dataset.alertFilter;renderAlerts();}));
document.querySelectorAll('.nav-link').forEach(a=>a.addEventListener('click',()=>{document.querySelectorAll('.nav-link').forEach(x=>x.classList.remove('active'));a.classList.add('active');}));
window.addEventListener('resize',drawTraffic);

refresh();setInterval(refresh,2500);
