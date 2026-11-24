# 4.2: Tráfico en vivo rehecho: gráfica de bajada/subida, categorías de programa y de servicio,
# dueño y país del destino, agrupado por programa y filtros.

t = doc.t
a = t.index('  <div class="page fill" id="p-traffic">')
b = t.index('  <div class="page fill" id="p-clean">')
doc.t = t[:a] + r'''  <div class="page fill" id="p-traffic">
    <div class="phead"><div class="grow"><h1>Tráfico de red en vivo</h1><div class="sub">${SUBS.traffic}</div></div>
      <label class="lsearch" style="max-width:300px"><i class="ic">${ic('search')}</i><input id="tq" placeholder="Programa, web, IP, país, servicio…" autocomplete="off"><button class="lsx" id="tqx" tabindex="-1">×</button></label>
      <div class="seg" id="tView"><button data-v="group" class="on" onclick="trSetView('group')">Por programa</button><button data-v="list" onclick="trSetView('list')">Todas</button></div>
      <button class="btn sm" id="tPause" onclick="toggleTraffic()"><i class="ic">${ic('bolt')}</i>En vivo</button></div>
    <div class="tr-scroll">
    <div class="tr-top">
      <div class="card tr-chart">
        <div class="tr-ch"><div><b>Velocidad de la conexión</b><small>últimos 2 minutos · todas las tarjetas de red</small></div>
          <div class="tr-leg" id="tLeg"></div></div>
        <div class="tr-cv"><canvas id="trCanvas"></canvas><div class="tr-tip" id="trTip"></div></div>
      </div>
      <div class="card tr-side">
        <div class="tr-kpis" id="tKpis"></div>
        <div class="tr-dest"><small>A dónde se conecta</small><div class="tr-stack" id="tStack"></div><div class="tr-sleg" id="tStackLeg"></div></div>
      </div>
    </div>
    <div id="tAnalysis"></div>
    <div class="tr-filters" id="tFilters"></div>
    <div class="card tr-table">
      <div class="trh"><div>Programa</div><div>Protocolo</div><div>Destino</div><div>Servicio</div><div>Estado</div><div>Desde</div></div>
      <div id="tList"></div>
    </div>
    </div>
  </div>

''' + t[b:]

t = doc.t
a = t.index('const TR = { on:true, data:null, q:\'\', timer:0 };')
b = t.index('function toggleItem(id){')
doc.t = t[:a] + r'''const TR = { on:true, data:null, q:'', timer:0, view:'group', f:'all', open:{}, hover:-1 };
const SCOPECOL = {Internet:'var(--accent)', LAN:'var(--green)', Local:'var(--text-4)'};
const TCAT = {'Navegador':['#3b82f6','globe'], 'Sistema Windows':['#7c8798','win'], 'Comunicación':['#8b5cf6','mail'], 'Nube y sincronización':['#06b6d4','save'], 'Juegos':['#ec4899','target'],
  'Música y vídeo':['#22c55e','pulse'], 'Seguridad':['#14b8a6','shield'], 'Desarrollo':['#f97316','code'], 'Actualizaciones':['#eab308','dl'], 'Apps de la Tienda':['#6366f1','grid'], 'Otros programas':['#94a3b8','box']};
const TSVC = {'Web segura':['g','lock'], 'Web sin cifrar':['a','globe'], 'DNS':['n','list'], 'Correo':['v','mail'], 'Acceso remoto':['r','pc'], 'Archivos compartidos':['a','folder'], 'Hora':['n','clock'],
  'VPN':['b','lock'], 'Llamadas y vídeo':['v','bell'], 'Bases de datos':['b','server'], 'Juegos':['v','target'], 'Sospechoso':['r','alert'], 'Otro':['n','net']};
function bps(n){ n = n||0; if (n < 1024) return Math.round(n)+' B/s'; if (n < 1048576) return (n/1024).toFixed(1)+' KB/s'; return (n/1048576).toFixed(2)+' MB/s'; }
function bitsTxt(n){ n = (n||0) * 8; if (n < 1e3) return Math.round(n)+' bit/s'; if (n < 1e6) return (n/1e3).toFixed(0)+' kbit/s'; if (n < 1e9) return (n/1e6).toFixed(1)+' Mbit/s'; return (n/1e9).toFixed(2)+' Gbit/s'; }
function updateTrafficBtn(){ const b = $('#tPause'); if (b) { b.innerHTML = `<i class="ic">${ic(TR.on?'bolt':'refresh')}</i>${TR.on?'En vivo':'Pausado'}`; b.classList.toggle('live', TR.on); } }
function startTraffic(){ TR.on = true; updateTrafficBtn(); pollTraffic(); trBindChart(); }
function stopTraffic(){ clearTimeout(TR.timer); TR.timer = 0; }
function toggleTraffic(){ TR.on = !TR.on; updateTrafficBtn(); if (TR.on) pollTraffic(); else stopTraffic(); }
function trSetView(v){ TR.view = v; document.querySelectorAll('#tView button').forEach(b => b.classList.toggle('on', b.dataset.v === v)); renderTraffic(); }
function trSetF(f){ TR.f = TR.f === f ? 'all' : f; renderTraffic(); }
async function pollTraffic(){
  if (S.page !== 'traffic') { stopTraffic(); return; }
  try { TR.data = await caTraffic(); renderTraffic(); } catch(e){}
  if (TR.on && S.page === 'traffic') { clearTimeout(TR.timer); TR.timer = setTimeout(pollTraffic, 2000); }
}
function trAgo(ms){ if (!ms) return ''; const s = Math.max(0, Math.round((Date.now() - ms) / 1000)); return s < 60 ? 'ahora' : s < 3600 ? `${Math.round(s/60)} min` : `${Math.round(s/3600)} h`; }
function trMatch(c){
  const q = TR.q;
  if (q && !((c.proc||'')+' '+(c.host||'')+' '+(c.remote||'')+' '+(c.svc||'')+' '+(c.svcCat||'')+' '+(c.org||'')+' '+(c.cc||'')+' '+(c.cat||'')+' '+(c.path||'')).toLowerCase().includes(q)) return false;
  const f = TR.f;
  if (f === 'internet') return c.scope === 'Internet';
  if (f === 'lan') return c.scope === 'LAN';
  if (f === 'susp') return !!c.risk;
  if (f === 'in') return c.dir === 'entra';
  if (f.startsWith('cat:')) return c.cat === f.slice(4);
  return true;
}
function renderTraffic(){
  const d = TR.data; if (!d || !$('#tKpis')) return;
  const cs = d.conns || [];
  const susp = cs.filter(c => c.risk);
  const progs = new Set(cs.map(c => c.pid)).size;
  const inbound = cs.filter(c => c.dir === 'entra').length;
  $('#tLeg').innerHTML = `<span class="tl-i" style="--c:var(--green)"><i></i><span><small>Bajada</small><b>${bps(d.inBps)}</b><em>máx. ${bps(d.peakIn)}</em></span></span>
    <span class="tl-i" style="--c:var(--accent)"><i></i><span><small>Subida</small><b>${bps(d.outBps)}</b><em>máx. ${bps(d.peakOut)}</em></span></span>`;
  const k = (label, v, hint, col, f) => `<button class="tk ${TR.f === f ? 'on' : ''}" style="--c:${col}" onclick="trSetF('${f}')"><small>${label}</small><b>${v}</b><em>${hint}</em></button>`;
  $('#tKpis').innerHTML = k('Conexiones', cs.length, `${progs} programa${progs === 1 ? '' : 's'}`, 'var(--accent)', 'all')
    + k('A Internet', d.internet || 0, `${cs.filter(c => c.scope === 'LAN').length} en la red local`, 'var(--vio)', 'internet')
    + k('Entrantes', inbound, inbound ? 'alguien se conecta a ti' : 'nadie se conecta al equipo', inbound ? 'var(--amber)' : 'var(--green)', 'in')
    + k('Sospechosas', susp.length, susp.length ? 'revísalas abajo' : 'todo normal', susp.length ? 'var(--red)' : 'var(--green)', 'susp');
  const sc = {Internet:0, LAN:0, Local:0}; cs.forEach(c => sc[c.scope || 'Local'] = (sc[c.scope || 'Local'] || 0) + 1);
  const tot = Math.max(1, cs.length);
  const scl = [['Internet','Internet','var(--accent)'],['LAN','Red local','var(--green)'],['Local','Este equipo','var(--text-4)']];
  $('#tStack').innerHTML = scl.map(([k2, , col]) => sc[k2] ? `<i style="flex:${sc[k2]};background:${col}" title="${sc[k2]}"></i>` : '').join('') || '<i style="flex:1;background:var(--track)"></i>';
  $('#tStackLeg').innerHTML = scl.map(([k2, n, col]) => `<span><i style="background:${col}"></i>${n}<b>${sc[k2] || 0}</b><em>${Math.round(100 * (sc[k2] || 0) / tot)} %</em></span>`).join('');
  renderTrafficAnalysis(susp);
  // categorías de programa (con número) para filtrar
  const cats = {}; cs.forEach(c => cats[c.cat || 'Otros programas'] = (cats[c.cat || 'Otros programas'] || 0) + 1);
  const ck = Object.entries(cats).sort((x, y) => y[1] - x[1]);
  $('#tFilters').innerHTML = `<div class="chips">${[['all','Todas',cs.length],['internet','Internet',d.internet||0],['lan','Red local',sc.LAN],['susp','Sospechosas',susp.length]].map(([f, n, c]) => `<button class="chip ${TR.f === f ? 'on' : ''}" onclick="TR.f='${f}';renderTraffic()">${n}<span class="n">${c}</span></button>`).join('')}</div>
    <div class="tr-cats">${ck.map(([c, n]) => { const m = TCAT[c] || TCAT['Otros programas']; return `<button class="tcat ${TR.f === 'cat:' + c ? 'on' : ''}" style="--c:${m[0]}" onclick="trSetF('cat:${esc(c)}')"><i class="ic">${ic(m[1])}</i>${esc(c)}<b>${n}</b></button>`; }).join('')}</div>`;
  const rows = cs.filter(trMatch);
  if (!rows.length) { $('#tList').innerHTML = `<div class="empty">${TR.q || TR.f !== 'all' ? 'Nada coincide con el filtro.' : 'Sin conexiones activas ahora mismo.'}</div>`; trDraw(); return; }
  if (TR.view === 'list') $('#tList').innerHTML = rows.map(c => trafficRow(c, false)).join('');
  else {
    const g = {}; rows.forEach(c => { const key = c.proc + '|' + (c.path || ''); (g[key] = g[key] || []).push(c); });
    const groups = Object.values(g).sort((x, y) => (y.some(c => c.risk) - x.some(c => c.risk)) || y.length - x.length);
    $('#tList').innerHTML = groups.map(l => {
      const c0 = l[0], key = c0.proc + '|' + (c0.path || ''), open = TR.open[key] || l.some(c => c.risk) || groups.length === 1;
      const m = TCAT[c0.cat] || TCAT['Otros programas'];
      const dests = new Set(l.map(c => c.host || c.org || splitRemote(c.remote)[0]));
      const orgs = [...new Set(l.map(c => c.org).filter(Boolean))].slice(0, 3);
      const risk = l.find(c => c.risk);
      return `<div class="trg ${risk ? 'risk ' + (risk.risk === 'Alerta' ? 'r' : 'a') : ''} ${open ? 'open' : ''}">
        <div class="trg-h" onclick="TR.open['${esc(key).replace(/\\/g, '\\\\').replace(/'/g, "\\'")}']=${!open};renderTraffic()">
          <i class="ic chev">${ic('chev')}</i><span class="pr-av" style="background:${hashC(c0.proc)}">${esc((c0.proc[0] || '?').toUpperCase())}</span>
          <div class="trg-n"><b>${esc(c0.proc)}</b><small>${esc(c0.path || 'ruta protegida por Windows')}</small></div>
          <span class="tcat sm" style="--c:${m[0]}"><i class="ic">${ic(m[1])}</i>${esc(c0.cat || 'Otros programas')}</span>
          <span class="trg-m"><b>${l.length}</b> conexi${l.length === 1 ? 'ón' : 'ones'} · <b>${dests.size}</b> destino${dests.size === 1 ? '' : 's'}${orgs.length ? ` · ${orgs.map(esc).join(', ')}` : ''}</span>
          ${risk ? `<span class="st st-${risk.risk === 'Alerta' ? 'r' : 'a'}">${stIcon(risk.risk === 'Alerta' ? 'Vulnerable' : 'Revisar')}<span>${risk.risk}</span></span>` : ''}
        </div>
        ${open ? `<div class="trg-b">${l.map(c => trafficRow(c, true)).join('')}</div>` : ''}</div>`;
    }).join('');
  }
  trDraw();
}
function renderTrafficAnalysis(susp){
  const box = $('#tAnalysis'); if (!box) return;
  if (!susp.length) { box.innerHTML = `<div class="tan-ok"><i class="ic">${ic('check')}</i>Nada sospechoso ahora mismo. Se vigila: programas en carpetas temporales, componentes de Windows suplantados, puertos de control remoto y tráfico de administración saliendo a Internet.</div>`; return; }
  const alerta = susp.filter(c => c.risk === 'Alerta'), revisar = susp.filter(c => c.risk === 'Revisar');
  const dest = c => c.host ? c.host : c.remote;
  const item = c => `<div class="tan-item" onclick="TR.q='${esc((c.proc||'').toLowerCase().replace(/'/g,''))}';$('#tq').value='${esc(c.proc||'')}';$('#tq').parentElement.classList.add('has');renderTraffic()" style="color:${c.risk==='Alerta'?'var(--red)':'var(--amber)'}">
    <span class="tdot"></span><div class="ti"><b>${esc(c.proc)} <span style="color:var(--text-3);font-weight:500">· ${esc(c.proto)} → ${esc(dest(c))}${c.org ? ' · ' + esc(c.org) : ''}${c.cc ? ' (' + esc(c.cc) + ')' : ''}</span></b><div class="d">${esc(c.path||'')}</div><div class="w">${esc(c.note||'')}</div></div></div>`;
  let html = '';
  if (alerta.length) html += `<div class="tan-card crit"><div class="tan-hd"><i class="ic">${ic('alert')}</i>${alerta.length} conexión(es) de alto riesgo</div>${alerta.map(item).join('')}</div>`;
  if (revisar.length) html += `<div class="tan-card" style="${alerta.length?'margin-top:12px':''}"><div class="tan-hd"><i class="ic">${ic('alert')}</i>${revisar.length} conexión(es) a revisar</div>${revisar.map(item).join('')}</div>`;
  box.innerHTML = html;
}
function splitRemote(r){ r = String(r||''); const i = r.lastIndexOf(':'); return i < 0 ? [r, ''] : [r.slice(0, i).replace(/[\[\]]/g, ''), r.slice(i+1)]; }
function trafficRow(c, inGroup){
  const [rip, rport] = splitRemote(c.remote);
  const own = [c.org, c.cc].filter(Boolean);
  const dest = c.scope === 'Local' ? '<b>este equipo</b><small>conexión interna entre programas</small>'
    : `<b>${esc(c.host || (c.org ? c.org : rip))}</b><small><span class="mono">${esc(rip)}${rport ? ':' + rport : ''}</span>${own.length ? ` · ${c.org && c.host ? esc(c.org) + ' · ' : ''}${c.cc ? `<span class="cc">${esc(c.cc)}</span>` : ''}` : ''}${c.scope === 'LAN' ? ' · red local' : ''}</small>`;
  const sv = TSVC[c.svcCat] || TSVC['Otro'];
  const stc = c.state === 'Conectada' ? 'g' : c.state === 'Conectando' ? 'a' : 'n';
  const m = TCAT[c.cat] || TCAT['Otros programas'];
  return `<div class="trr ${c.risk ? 'risk ' + (c.risk === 'Alerta' ? 'r' : 'a') : ''}" title="${esc(c.note || '')}">
    <div class="pc">${inGroup ? `<span class="tr-dir ${c.dir}">${c.dir === 'entra' ? '↙' : '↗'}</span><span class="tr-lp mono">${esc(splitRemote(c.local)[1] ? 'puerto ' + splitRemote(c.local)[1] : '')}</span>` : `<span class="pr-av sm" style="background:${hashC(c.proc)}">${esc((c.proc[0]||'?').toUpperCase())}</span><div><b>${esc(c.proc)}</b><small style="color:${m[0]}">${esc(c.cat || '')}</small></div>`}</div>
    <div><span class="tp">${esc(c.proto)}${c.ipv6 ? '<em>IPv6</em>' : ''}</span>${!inGroup ? `<span class="tr-dir ${c.dir}" title="${c.dir === 'entra' ? 'Entrante' : 'Saliente'}">${c.dir === 'entra' ? '↙' : '↗'}</span>` : ''}</div>
    <div class="td">${dest}</div>
    <div><span class="tsv t-${sv[0]}"><i class="ic">${ic(sv[1])}</i>${esc(c.svcCat || 'Otro')}</span><small class="tsv-d">${esc(c.svc || '')}</small></div>
    <div><span class="tst t-${stc}"><i></i>${esc(c.state || '—')}</span></div>
    <div class="mono tsm">${trAgo(c.since)}</div></div>`;
}
// ---- gráfica de bajada / subida ----
function trBindChart(){
  const cv = $('#trCanvas'); if (!cv || cv._b) return; cv._b = 1;
  cv.addEventListener('mousemove', e => { const r = cv.getBoundingClientRect(); TR.hover = (e.clientX - r.left) / r.width; trDraw(); });
  cv.addEventListener('mouseleave', () => { TR.hover = -1; trDraw(); });
  window.addEventListener('resize', () => { if (S.page === 'traffic') trDraw(); });
}
function niceMax(v){ if (v <= 0) return 1024; const p = Math.pow(2, Math.ceil(Math.log2(v * 1.15))); return Math.max(1024, p); }
function trDraw(){
  const cv = $('#trCanvas'), d = TR.data; if (!cv || !d) return;
  const W = cv.clientWidth, H = cv.clientHeight; if (!W || !H) return;
  const dpr = window.devicePixelRatio || 1; if (cv.width !== W * dpr || cv.height !== H * dpr) { cv.width = W * dpr; cv.height = H * dpr; }
  const g = cv.getContext('2d'); g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, W, H);
  const h = d.hist || [], n = 120;
  const pad = {l: 64, r: 8, t: 8, b: 20}, cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;
  const max = niceMax(Math.max(...h.map(p => Math.max(p.in, p.out)), 1));
  const grid = cssv('--line') || '#e5e7eb', txt = cssv('--text-4') || '#999';
  g.font = '10.5px Inter, sans-serif'; g.fillStyle = txt; g.strokeStyle = grid; g.lineWidth = 1;
  for (let i = 0; i <= 4; i++) { const y = pad.t + ch * i / 4; g.beginPath(); g.moveTo(pad.l, Math.round(y) + .5); g.lineTo(W - pad.r, Math.round(y) + .5); g.stroke(); g.textAlign = 'right'; g.fillText(bps(max * (4 - i) / 4).replace('.0 ', ' '), pad.l - 8, y + 3.5); }
  [[0, 'hace 2 min', 'left'], [.5, 'hace 1 min', 'center'], [1, 'ahora', 'right']].forEach(([f, s, al]) => { g.textAlign = al; g.fillText(s, pad.l + cw * f, H - 5); });
  const X = i => pad.l + cw * (i + (n - h.length)) / (n - 1), Y = v => pad.t + ch - ch * Math.min(1, v / max);
  const line = (k, col) => {
    if (h.length < 2) return;
    const grad = g.createLinearGradient(0, pad.t, 0, pad.t + ch); grad.addColorStop(0, col + '55'); grad.addColorStop(1, col + '05');
    g.beginPath(); g.moveTo(X(0), Y(h[0][k]));
    for (let i = 1; i < h.length; i++) { const x0 = X(i - 1), x1 = X(i), y0 = Y(h[i - 1][k]), y1 = Y(h[i][k]), mx = (x0 + x1) / 2; g.bezierCurveTo(mx, y0, mx, y1, x1, y1); }
    g.strokeStyle = col; g.lineWidth = 2; g.stroke();
    g.lineTo(X(h.length - 1), pad.t + ch); g.lineTo(X(0), pad.t + ch); g.closePath(); g.fillStyle = grad; g.fill();
  };
  const cIn = cssHex('--green', '#12a06b'), cOut = cssHex('--accent', '#2f7de1');
  line('in', cIn); line('out', cOut);
  if (h.length) { const i = h.length - 1; [['in', cIn], ['out', cOut]].forEach(([k, c]) => { g.beginPath(); g.arc(X(i), Y(h[i][k]), 3.5, 0, 7); g.fillStyle = c; g.fill(); }); }
  const tip = $('#trTip');
  if (TR.hover >= 0 && h.length) {
    const xi = Math.round((TR.hover * W - pad.l) / cw * (n - 1)) - (n - h.length);
    const i = Math.max(0, Math.min(h.length - 1, xi)), p = h[i], x = X(i);
    g.strokeStyle = txt; g.setLineDash([3, 3]); g.beginPath(); g.moveTo(x + .5, pad.t); g.lineTo(x + .5, pad.t + ch); g.stroke(); g.setLineDash([]);
    tip.style.display = 'block'; tip.style.left = Math.min(W - 150, Math.max(0, x + 10)) + 'px';
    tip.innerHTML = `<small>${new Date(p.t).toLocaleTimeString('es-ES')}</small><span style="color:${cIn}">↓ ${bps(p.in)}</span><span style="color:${cOut}">↑ ${bps(p.out)}</span><small>${bitsTxt(p.in)}</small>`;
  } else tip.style.display = 'none';
}
function cssHex(v, def){ const s = (cssv(v) || '').trim(); return /^#[0-9a-f]{6}$/i.test(s) ? s : def; }

''' + t[b:]
rep("traffic:'Conexiones activas del equipo, con análisis de las que parecen sospechosas.'",
    "traffic:'Qué programas se conectan, a dónde (web, empresa y país), para qué y a qué velocidad. Lo sospechoso sale arriba.'")
