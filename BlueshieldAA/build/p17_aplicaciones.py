# 4.2: Mantenimiento → Aplicaciones: todo lo instalado (programas, componentes y apps de la
# Tienda) leído del registro, con tamaño, fecha, actualizaciones pendientes y desinstalar.

rep("const LIST_PAGES = ['updates','protect','changes','net','hw','apps','events'];", "const LIST_PAGES = ['updates','protect','changes','net','events'];")
rep("apps:'Todas las aplicaciones del equipo, también las ocultas y las de Microsoft Store.'",
    "apps:'Todo lo instalado en el equipo: programas, componentes y apps de Microsoft Store. Con tamaño, fecha y si hay versión nueva.'")
rep('  <div class="page fill" id="p-clean">', r'''  <div class="page fill" id="p-apps">
    <div class="phead"><div class="grow"><h1>Aplicaciones</h1><div class="sub">${SUBS.apps}</div></div><div id="apSubtabs"></div>
      <label class="lsearch" style="max-width:280px"><i class="ic">${ic('search')}</i><input id="apq" placeholder="Buscar programa o editor…" autocomplete="off" oninput="AP.q=this.value.toLowerCase().trim();apRender()"></label>
      <button class="btn sm" onclick="apLoad(true)"><i class="ic">${ic('refresh')}</i>Volver a leer</button></div>
    <div class="ap-sum" id="apSum"></div>
    <div class="ap-bar"><div class="chips" id="apKinds"></div><span class="sp"></span><div class="seg" id="apSort"></div></div>
    <div class="card ap-card"><div class="ap-hd"><div>Aplicación</div><div>Versión</div><div>Tamaño</div><div>Instalada</div><div></div></div><div id="apList" class="ap-list"></div></div>
  </div>

  <div class="page fill" id="p-clean">''')
rep("  if (p === 'clean') clInit(); else clStop();", "  if (p === 'clean') clInit(); else clStop();\n  if (p === 'apps') apInit(); else apStop();")
rep("/* ====================== Procesos ====================== */", r"""/* ====================== Aplicaciones ====================== */
const AP = {l:null, q:'', kind:'Programa', sort:'name', open:null, watch:0, busy:false};
function apInit(){ $('#apSubtabs').innerHTML = subtabsHTML('apps'); if (!AP.l) apRender(); apLoad(); }
function apStop(){ clearInterval(AP.watch); AP.watch = 0; }
async function apLoad(manual){ if (AP.busy) return; AP.busy = true; try { AP.l = await caApps() || []; } catch (e) {} AP.busy = false; apRender(); if (manual) toast(`Lista al día: ${AP.l.length} aplicaciones.`); }
function apFmtDate(s){ if (!s) return '—'; const d = new Date(s + 'T00:00:00'); return d.toLocaleDateString('es-ES', {day:'2-digit', month:'short', year:'numeric'}); }
function apRender(){
  const all = AP.l; const box = $('#apList'); if (!box) return;
  if (!all) { box.innerHTML = '<div class="dg-empty">Leyendo lo instalado…</div>'; return; }
  const progs = all.filter(a => a.kind === 'Programa'), size = all.reduce((x, a) => x + (a.size || 0), 0);
  const month = new Date(Date.now() - 30 * 864e5).toISOString().slice(0, 10);
  const recent = all.filter(a => a.installed && a.installed >= month).length, upd = all.filter(a => a.update).length;
  const card = (c, i, k, v, h, f) => `<button class="pst ${f && AP.kind === f ? 'on' : ''}" style="--c:${c}" ${f ? `onclick="AP.kind='${f}';apRender()"` : ''}><span class="pst-ic"><i class="ic">${ic(i)}</i></span><span class="pst-t"><small>${k}</small><b>${v}</b><em>${h}</em></span></button>`;
  $('#apSum').innerHTML = card('var(--accent)', 'grid', 'Programas', progs.length, `${all.length} en total contando componentes`, 'Programa')
    + card('var(--vio)', 'disk', 'Ocupan', fBytes(size), 'según lo que dice cada programa')
    + card('var(--green)', 'clock', 'Nuevos este mes', recent, recent ? 'instalados en los últimos 30 días' : 'nada nuevo', 'recent')
    + card(upd ? 'var(--amber)' : 'var(--green)', 'dl', 'Con versión nueva', upd, upd ? 'pulsa para verlas' : 'todo al día', 'update');
  const kinds = [['Programa','Programas'],['Componente','Componentes'],['Tienda','Microsoft Store'],['all','Todas']];
  $('#apKinds').innerHTML = kinds.map(([k, n]) => `<button class="chip ${AP.kind === k ? 'on' : ''}" onclick="AP.kind='${k}';apRender()">${n}<span class="n">${k === 'all' ? all.length : all.filter(a => a.kind === k).length}</span></button>`).join('');
  $('#apSort').innerHTML = [['name','Nombre'],['size','Tamaño'],['date','Más recientes']].map(([k, n]) => `<button class="${AP.sort === k ? 'on' : ''}" onclick="AP.sort='${k}';apRender()">${n}</button>`).join('');
  let l = all;
  if (AP.kind === 'recent') l = l.filter(a => a.installed && a.installed >= month);
  else if (AP.kind === 'update') l = l.filter(a => a.update);
  else if (AP.kind !== 'all') l = l.filter(a => a.kind === AP.kind);
  if (AP.q) l = l.filter(a => (a.name + ' ' + (a.publisher || '')).toLowerCase().includes(AP.q));
  if (AP.sort === 'size') l = [...l].sort((x, y) => (y.size || 0) - (x.size || 0));
  if (AP.sort === 'date') l = [...l].sort((x, y) => (y.installed || '').localeCompare(x.installed || ''));
  const max = Math.max(1, ...l.map(a => a.size || 0));
  box.innerHTML = l.length ? l.map(a => {
    const open = AP.open === a.id, id = esc(a.id).replace(/'/g, "\\'");
    return `<div class="ap-row ${open ? 'open' : ''}" onclick="AP.open=AP.open==='${id}'?null:'${id}';apRender()">
      <div class="ap-n"><span class="pr-av" style="background:${hashC(a.name)}">${esc((a.name[0] || '?').toUpperCase())}</span><div><b>${esc(a.name)}</b><small>${esc(a.publisher || '—')}${a.kind !== 'Programa' ? ` · <span class="ap-k">${a.kind === 'Tienda' ? 'Microsoft Store' : 'Componente'}</span>` : ''}</small></div></div>
      <div class="mono ap-v">${esc(a.version || '—')}${a.update ? `<span class="ap-up" title="Hay una versión nueva">→ ${esc(a.update)}</span>` : ''}</div>
      <div class="ap-s">${a.size ? `<span class="ap-sb"><i style="width:${Math.max(3, 100 * a.size / max)}%"></i></span><span class="mono">${fBytes(a.size)}</span>` : '<span class="ap-na">—</span>'}</div>
      <div class="ap-d">${apFmtDate(a.installed)}</div>
      <div class="ap-a" onclick="event.stopPropagation()">${a.update ? `<button class="btn sm" onclick="showPage('updates')">Actualizar</button>` : ''}${a.canRemove ? `<button class="btn sm ghost" onclick="apUninstall('${id}')">Desinstalar</button>` : ''}</div></div>
      ${open ? `<div class="ap-det"><div class="pr-kv"><span>Carpeta</span><code>${esc(a.location || 'no lo indica')}</code></div><div class="pr-kv"><span>Para</span><b>${esc(a.scope || '—')}</b></div><div class="pr-kv"><span>Tipo</span><b>${esc(a.arch || '—')}</b></div>
        <div class="pr-acts" onclick="event.stopPropagation()"><button class="btn sm" onclick="apReveal('${id}')"><i class="ic">${ic('folder')}</i>Abrir su carpeta</button>${a.canRemove ? `<span class="sp"></span><button class="btn sm danger" onclick="apUninstall('${id}')"><i class="ic">${ic('trash')}</i>Desinstalar</button>` : ''}</div></div>` : ''}`;
  }).join('') : `<div class="dg-empty">${AP.q ? 'Nada coincide con la búsqueda.' : 'No hay nada en este grupo.'}</div>`;
}
async function apReveal(id){ const m = await caAppReveal(id); if (m) toast(esc(m)); }
function apUninstall(id){
  const a = (AP.l || []).find(x => x.id === id); if (!a) return;
  modal('Desinstalar ' + esc(a.name), `<p style="margin-top:0">Se abrirá el desinstalador del propio programa${a.kind === 'Tienda' ? ' (en Configuración de Windows)' : ''}: sigue sus pasos o cancélalo si cambias de idea.</p><p class="help">Cuando termine, la lista se actualiza sola.</p>`,
    [{t:'Cancelar'}, {t:'Abrir el desinstalador', c:'pri', f: async () => { const m = await caAppUninstall(id); if (m) toast(esc(m)); apWatch(); }}]);
}
// después de desinstalar se vuelve a leer la lista cada pocos segundos durante 3 minutos
function apWatch(){ clearInterval(AP.watch); let n = 0; AP.watch = setInterval(() => { if (S.page !== 'apps' || ++n > 45) { clearInterval(AP.watch); return; } apLoad(); }, 4000); }

/* ====================== Procesos ====================== */""")
