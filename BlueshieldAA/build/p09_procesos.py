# Eventos pasa a tener dos subapartados: Visor de eventos y Procesos (lo que corre ahora,
# con árbol, firma, red y avisos; analizar o terminar un proceso).
rep("  {id:'events', t:'Eventos', badge:'e', i:'pulse'},",
    "  {id:'evgrp', t:'Eventos', i:'pulse', sub:[['events','Visor de eventos'],['procs','Procesos']]},")
rep("const PAGE_ALIAS = {pentest:'protect',", "const PAGE_ALIAS = {evgrp:'events', pentest:'protect',")
rep("${['changes','protect','net','clean'].includes(x[0])?", "${['changes','protect','net','clean','events'].includes(x[0])?")
rep("const TITLES = {ransom:'Anti-ransomware',", "const TITLES = {procs:'Procesos en marcha', ransom:'Anti-ransomware',")
rep("const SUBS = {ransom:", "const SUBS = {procs:'Lo que se está ejecutando ahora en el equipo: quién lo lanzó, si está firmado, si usa la red y lo que merece la pena revisar.', ransom:")
rep("  if (p === 'traffic') startTraffic(); else stopTraffic();",
    "  if (p === 'traffic') startTraffic(); else stopTraffic();\n  if (p === 'procs') startProcs(); else stopProcs();")
rep('  <div class="page fill" id="p-log">',
    '''  <div class="page fill" id="p-procs">
    <div class="phead"><div class="grow"><h1>Procesos en marcha</h1><div class="sub">${SUBS.procs}</div></div><div id="prSubtabs"></div>
      <label class="lsearch" style="max-width:300px"><i class="ic">${ic('search')}</i><input id="prq" placeholder="Buscar proceso, ruta, usuario…" autocomplete="off" oninput="PR.q=this.value;prRender()"></label>
      <div class="seg" id="prView"><button data-v="tree" class="on" onclick="prSetView('tree')">Árbol</button><button data-v="flag" onclick="prSetView('flag')">A revisar</button><button data-v="cpu" onclick="prSetView('cpu')">Más CPU</button></div></div>
    <div class="tstats" id="prStats"></div>
    <div class="card pr-card">
      <div class="pr-hd"><div>Proceso</div><div>PID</div><div>Usuario</div><div>CPU</div><div>Memoria</div><div>Firma</div><div>Red</div><div>Estado</div></div>
      <div id="prList" class="pr-list"></div>
    </div>
  </div>

  <div class="page fill" id="p-log">''')
rep("/* ====================== ventana de progreso cíber ====================== */",
r"""/* ====================== Procesos ====================== */
const PR = {timer:0, d:null, q:'', view:'tree', open:null};
function startProcs(){ $('#prSubtabs').innerHTML = subtabsHTML('procs'); prLoad(); clearInterval(PR.timer); PR.timer = setInterval(() => { if (S.page === 'procs' && !document.hidden) prLoad(); }, 5000); }
function stopProcs(){ clearInterval(PR.timer); PR.timer = 0; }
async function prLoad(){ try { PR.d = await caProcesses(); } catch (e) { return; } prRender(); }
function prSetView(v){ PR.view = v; document.querySelectorAll('#prView button').forEach(b => b.classList.toggle('on', b.dataset.v === v)); prRender(); }
const SIGC = {'Microsoft':['g','Microsoft'], 'Firmado':['g','Firmado'], 'Sin firmar':['a','Sin firmar'], 'Firma no válida':['r','No válida'], '':['n','—']};
function prRender(){
  const d = PR.d; if (!d) { $('#prList').innerHTML = '<div class="dg-empty">Leyendo los procesos…</div>'; return; }
  const top = [...d.procs].sort((a, b) => b.cpu - a.cpu)[0];
  $('#prStats').innerHTML = [['Procesos', d.total, ''], ['A revisar', d.flagged, d.flagged ? 'var(--red-ink)' : ''], ['Sin firmar', d.unsigned, d.unsigned ? 'var(--amber-ink)' : ''], ['Usan la red', d.net, ''], ['Más CPU', top ? `${esc(top.name)} · ${top.cpu} %` : '—', '']]
    .map(([k, v, c]) => `<div class="tstat"><small>${k}</small><b style="${c ? 'color:' + c : ''}">${v}</b></div>`).join('');
  const q = PR.q.trim().toLowerCase();
  let l = d.procs;
  if (q) l = l.filter(p => [p.name, p.path, p.user, p.company, p.desc, String(p.pid), p.cmd].some(x => String(x||'').toLowerCase().includes(q)));
  if (PR.view === 'flag') l = l.filter(p => p.flag || p.signed === 'Sin firmar');
  if (PR.view === 'cpu') l = [...l].sort((a, b) => b.cpu - a.cpu || b.mem - a.mem).slice(0, 60);
  const tree = PR.view === 'tree' && !q;
  $('#prList').innerHTML = l.length ? l.map(p => {
    const s = SIGC[p.signed] || SIGC[''];
    const ind = tree ? Math.min(p.depth, 8) * 16 : 0;
    const st = p.flag === 'Alerta' ? pill('Vulnerable').replace('>Vulnerable<', '>Alerta<') : p.flag === 'Revisar' ? pill('Revisar') : '';
    const open = PR.open === p.pid;
    return `<div class="pr-row ${p.flag ? 'f-' + (p.flag === 'Alerta' ? 'r' : 'a') : ''} ${open ? 'open' : ''}" onclick="prToggle(${p.pid})">
      <div class="pr-n" style="padding-left:${ind}px">${tree && p.depth ? '<i class="pr-br"></i>' : ''}<span class="pr-av" style="background:${hashC(p.name)}">${esc((p.name[0]||'?').toUpperCase())}</span><div><b>${esc(p.name)}</b><small>${esc(p.desc || p.company || p.path || '')}</small></div></div>
      <div class="mono">${p.pid}</div><div class="pr-u">${esc((p.user||'').split('\\').pop() || '—')}</div>
      <div class="mono">${p.cpu ? p.cpu.toFixed(1) + ' %' : '·'}</div><div class="mono">${fBytes(p.mem)}</div>
      <div><span class="st st-${s[0]}">${stIcon(s[0] === 'g' ? 'Al día' : s[0] === 'r' ? 'Falló' : s[0] === 'a' ? 'Revisar' : 'Info')}<span>${s[1]}</span></span></div>
      <div class="mono">${p.conns || '·'}</div><div>${st}</div></div>
      ${open ? `<div class="pr-det">
        ${p.why ? `<div class="pr-why"><i class="ic">${ic('alert')}</i>${esc(p.why)}</div>` : ''}
        <div class="pr-kv"><span>Ruta</span><code>${esc(p.path || '(protegida por Windows)')}</code></div>
        <div class="pr-kv"><span>Línea de órdenes</span><code>${esc(p.cmd || '—')}</code></div>
        <div class="pr-kv"><span>Lanzado por</span><b>${esc((d.procs.find(x => x.pid === p.ppid) || {}).name || 'PID ' + p.ppid)}</b></div>
        <div class="pr-kv"><span>Firma</span><b>${esc(p.signer || p.signed || '—')}</b></div>
        <div class="pr-kv"><span>Empresa</span><b>${esc(p.company || '—')}</b></div>
        <div class="pr-kv"><span>En marcha desde</span><b>${p.start ? new Date(p.start).toLocaleString('es-ES') : '—'}</b></div>
        <div class="pr-acts" onclick="event.stopPropagation()">
          ${p.path ? `<button class="btn sm" onclick="prAnalyze(${p.pid})"><i class="ic">${ic('search')}</i>Analizar el archivo</button><button class="btn sm" onclick="caReveal(PR.d.procs.find(x=>x.pid===${p.pid}).path)"><i class="ic">${ic('folder')}</i>Mostrar en la carpeta</button>` : ''}
          ${p.conns ? `<button class="btn sm" onclick="showPage('traffic');setTimeout(()=>{const i=$('#tq');if(i){i.value=${JSON.stringify(p.name).replace(/"/g,'&quot;')};i.dispatchEvent(new Event('input'))}},300)"><i class="ic">${ic('net')}</i>Ver sus conexiones</button>` : ''}
          <span class="sp"></span><button class="btn sm danger" onclick="prKill(${p.pid})"><i class="ic">${ic('x')}</i>Terminar proceso</button></div>
      </div>` : ''}`;
  }).join('') : '<div class="dg-empty">No hay procesos que coincidan.</div>';
}
function prToggle(pid){ PR.open = PR.open === pid ? null : pid; prRender(); }
function prAnalyze(pid){ const p = PR.d.procs.find(x => x.pid === pid); if (!p || !p.path) return; showPage('scanfile'); setTimeout(() => faAnalyze(p.path), 200); }
function prKill(pid){
  const p = PR.d.procs.find(x => x.pid === pid); if (!p) return;
  modal('Terminar proceso', `<p style="margin-top:0">Se cerrará <b>${esc(p.name)}</b> (PID ${p.pid}) <b>a la fuerza</b>. Si es un programa con trabajo sin guardar, se perderá.</p>${p.flag ? '' : '<p class="help">No tiene ningún aviso: termínalo solo si sabes lo que es.</p>'}`,
    [{t:'Cancelar'}, {t:'Terminar', c:'pri', f: async () => { const m = await caProcKill(p.pid, p.name); toast(esc(m || p.name + ' terminado.')); prLoad(); }}]);
}

/* ====================== ventana de progreso cíber ====================== */""")
