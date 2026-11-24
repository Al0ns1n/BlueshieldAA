# Mantenimiento → Limpieza rehecha: explorador de espacio interactivo (como SizeTree/WinDirStat)
# con árbol por tamaño, mapa de rectángulos, qué se puede borrar y qué no, limpieza recomendada,
# archivos más grandes y la limpieza rápida de siempre (que ahora mide lo liberado de verdad).
rep("const LIST_PAGES = ['updates','protect','changes','net','hw','clean','apps','events'];",
    "const LIST_PAGES = ['updates','protect','changes','net','hw','apps','events'];")
rep("    : p === 'clean' ? $('#lSub').textContent : (SUBS[p] || '');", "    : (SUBS[p] || '');")
rep("  if (p === 'procs') startProcs(); else stopProcs();",
    "  if (p === 'procs') startProcs(); else stopProcs();\n  if (p === 'clean') clInit(); else clStop();")
rep("const SUBS = {procs:", "const SUBS = {clean:'Mira qué ocupa tu disco, qué se puede borrar sin miedo y qué conviene revisar antes.', procs:")
rep('  <div class="page fill" id="p-procs">', '''  <div class="page fill" id="p-clean">
    <div class="phead"><div class="grow"><h1>Limpieza</h1><div class="sub">${SUBS.clean}</div></div><div id="clSubtabs"></div></div>
    <div class="card cl-drive" id="clDrive"></div>
    <div class="cl-tabs" id="clTabs"></div>
    <div class="cl-body" id="clBody"></div>
    <div class="cl-sel" id="clSel"></div>
  </div>

  <div class="page fill" id="p-procs">''')
rep("/* ====================== Procesos ====================== */", r"""/* ====================== Limpieza: explorador de espacio ====================== */
const CL = {drives:[], drive:'', tab:'recs', path:'', view:null, recs:null, top:null, sel:{}, timer:0, scan:null, del:null, focus:null, lastDel:false};
const CLV = {borrar:['g','Se puede borrar','#12a06b'], cuidado:['a','Revisa antes','#d08a0b'], personal:['b','Personal','#2f7de1'], sistema:['r','Sistema','#8b5cf6'], '':['n','','#64748b']};
const CLACT = {hiber:'Desactivar hibernación', dism:'Limpiar componentes de Windows', storage:'Abrir Almacenamiento de Windows'};
function clBadge(c){ const v = CLV[(c||{}).level || ''] || CLV['']; if (!v[1]) return ''; const ico = {borrar:'Limpiable', cuidado:'Revisar', personal:'Info', sistema:'Abierto'}[c.level]; return `<span class="st st-${v[0]}">${stIcon(ico)}<span>${v[1]}</span></span>`; }
async function clInit(){
  $('#clSubtabs').innerHTML = subtabsHTML('clean');
  CL.drives = await caDrives() || [];
  if (!CL.drive && CL.drives.length) CL.drive = (CL.drives.find(d => d.sys) || CL.drives[0]).root;
  const p = await caDiskPoll(); CL.scan = p.scan; CL.del = p.del;
  if (CL.scan.state === 'escaneando') clWatch();
  if (CL.scan.state === 'listo' && !CL.view) await clLoad();
  clDraw();
}
function clStop(){ clearInterval(CL.timer); CL.timer = 0; }
function clWatch(){ clearInterval(CL.timer); CL.timer = setInterval(clTick, 700); }
async function clTick(){
  const p = await caDiskPoll(); const was = CL.scan && CL.scan.state, wasDel = CL.del && CL.del.running;
  CL.scan = p.scan; CL.del = p.del;
  if (was === 'escaneando' && CL.scan.state !== 'escaneando') { await clLoad(); clDraw(); }
  else if (wasDel && !CL.del.running) { clDelDone(); }
  else clDrawDrive(), clDrawSel();
  if (CL.scan.state !== 'escaneando' && !CL.del.running) clStop();
}
async function clLoad(){
  const v = await caDiskView(CL.path); if (v && v.ok) CL.view = v.view;
  CL.recs = await caDiskRecs(); CL.top = await caDiskTop();
}
async function clScan(root){
  CL.drive = root || CL.drive; CL.path = ''; CL.view = null; CL.recs = null; CL.top = null; CL.sel = {};
  const m = await caDiskScan(CL.drive); if (m) { toast(esc(m)); return; }
  CL.scan = {state:'escaneando', files:0, bytes:0, dirs:0, secs:0}; clDraw(); clWatch();
}
function clDraw(){ clDrawDrive(); clDrawTabs(); clDrawBody(); clDrawSel(); }
function clDrawDrive(){
  const s = CL.scan || {};
  const drives = CL.drives.map(d => { const used = d.total - d.free; const pct = Math.round(100 * used / d.total);
    return `<button class="cl-dv ${d.root === CL.drive ? 'on' : ''}" onclick="CL.drive='${d.root.replace(/\\/g, '\\\\')}';clDraw()"><b>${esc(d.root.slice(0, 2))}${d.label ? ' · ' + esc(d.label) : ''}</b>
      <i><em style="width:${pct}%;background:${pct > 90 ? 'var(--red)' : pct > 75 ? 'var(--amber)' : 'var(--accent)'}"></em></i><small>${fBytes(d.free)} libres de ${fBytes(d.total)}</small></button>`; }).join('');
  let st;
  if (s.state === 'escaneando') st = `<div class="cl-prog"><span class="cl-spin"></span><div><b>Analizando ${esc((s.root||CL.drive).slice(0, 2))}… ${fBytes(s.bytes)} en ${(s.files||0).toLocaleString('es-ES')} archivos</b><small class="mono">${esc(s.cur || '')}</small></div><button class="btn sm" onclick="caDiskCancel()">Cancelar</button></div>`;
  else if (s.state === 'listo') st = `<div class="cl-prog done"><i class="ic">${ic('check')}</i><div><b>${esc((s.root||'').slice(0, 2))} analizado: ${fBytes(s.bytes)} en ${(s.files||0).toLocaleString('es-ES')} archivos (${Math.round(s.secs)} s)</b><small>${s.denied ? s.denied + ' carpetas protegidas no se han podido leer.' : 'Pulsa una carpeta para entrar.'}</small></div><button class="btn sm" onclick="clScan()">Volver a analizar</button></div>`;
  else st = `<div class="cl-prog"><i class="ic">${ic('search')}</i><div><b>Elige una unidad y analízala</b><small>Se recorren todas las carpetas para ver qué ocupa espacio. No se borra nada sin que lo confirmes.</small></div><button class="btn pri" onclick="clScan()"><i class="ic">${ic('search')}</i>Analizar ${esc(CL.drive.slice(0, 2))}</button></div>`;
  $('#clDrive').innerHTML = `<div class="cl-dvs">${drives}</div>${st}`;
}
function clDrawTabs(){
  const n = (CL.recs || []).filter(r => r.class.level === 'borrar' && !r.class.action).reduce((a, r) => a + r.size, 0);
  const junk = S.items.filter(i => i.category === 'Limpieza' && ['Limpiable','Info'].includes(i.status)).reduce((a, i) => a + (i.bytes||0), 0);
  const tabs = [['recs', 'Se puede liberar' + (CL.recs ? ' · ' + fBytes(n) : '')], ['tree', 'Explorar carpetas'], ['top', 'Archivos más grandes'], ['quick', 'Limpieza rápida' + (junk ? ' · ' + fBytes(junk) : '')]];
  $('#clTabs').innerHTML = `<div class="chips">${tabs.map(t => `<button class="chip ${CL.tab === t[0] ? 'on' : ''}" onclick="CL.tab='${t[0]}';clDraw()">${t[1]}</button>`).join('')}</div>
    <div class="cl-leg">${['borrar','cuidado','personal','sistema'].map(k => `<span><i style="background:${CLV[k][2]}"></i>${CLV[k][1]}</span>`).join('')}</div>`;
}
function clNeedScan(){ return `<div class="card cl-empty"><i class="ic">${ic('search')}</i><b>Primero analiza la unidad</b><span>Tarda entre unos segundos y un par de minutos según lo lleno que esté el disco.</span>${CL.scan && CL.scan.state === 'escaneando' ? '' : `<button class="btn pri" onclick="clScan()">Analizar ${esc(CL.drive.slice(0, 2))}</button>`}</div>`; }
function clDrawBody(){
  const b = $('#clBody');
  if (CL.tab === 'quick') { b.innerHTML = clQuickHTML(); return; }
  if (!CL.view) { b.innerHTML = clNeedScan(); return; }
  if (CL.tab === 'recs') b.innerHTML = clRecsHTML();
  else if (CL.tab === 'top') b.innerHTML = `<div class="card cl-list">${clRows(CL.top || [], 'Archivos de más de 50 MB en toda la unidad', true)}</div>`;
  else { b.innerHTML = clTreeHTML(); clTreemap(); }
}
const clProtected = p => /^[a-z]:\\?$/i.test(p) || /^[a-z]:\\users(\\[^\\]+(\\(appdata|desktop|escritorio|documents|documentos|downloads|descargas|pictures|imágenes|videos|vídeos|music|música|onedrive[^\\]*))?)?$/i.test(p);
function clRow(e, max, showPath){
  const v = CLV[e.class.level || ''] || CLV[''];
  const can = !e.rest && e.class.level !== 'sistema' && !e.class.action && !e.denied && !clProtected(e.path);
  const pct = max ? Math.max(0.5, 100 * e.size / max) : 0;
  const on = !!CL.sel[e.path];
  const sub = showPath ? e.path : (e.dir ? `${(e.files||0).toLocaleString('es-ES')} archivos` : (e.mtime ? 'modificado ' + new Date(e.mtime * 1000).toLocaleDateString('es-ES') : ''));
  return `<div class="cl-row ${CL.focus === e.path ? 'focus' : ''} ${e.rest ? 'rest' : ''}" data-p="${esc(e.path)}" onclick="clClick(this.dataset.p, ${e.dir ? 1 : 0}, ${e.rest ? 1 : 0})">
    <label class="cl-ck ${can ? '' : 'off'}" onclick="event.stopPropagation()">${can ? `<input type="checkbox" ${on ? 'checked' : ''} onchange="clToggle(this.closest('.cl-row').dataset.p, ${e.size}, this.checked)">` : ''}</label>
    <span class="cl-ic" style="color:${v[2]}"><i class="ic">${ic(e.dir ? 'folder' : 'file')}</i></span>
    <div class="cl-nm"><b>${esc(e.name)}</b><small>${esc(sub)}</small></div>
    <div class="cl-bar"><i style="width:${pct}%;background:${v[2]}"></i></div>
    <div class="cl-sz mono">${fBytes(e.size)}</div>
    <div class="cl-bd">${e.class.action ? `<button class="btn sm" onclick="event.stopPropagation();clAction('${e.class.action}')">${CLACT[e.class.action]}</button>` : clBadge(e.class)}</div></div>`;
}
function clRows(l, title, showPath){
  const max = l.length ? l[0].size : 0;
  return `${title ? `<div class="cl-lh">${title}</div>` : ''}${l.length ? l.map(e => clRow(e, max, showPath)).join('') : '<div class="fa-empty" style="padding:20px">Nada por aquí.</div>'}`;
}
function clTreeHTML(){
  const v = CL.view;
  const crumbs = v.crumbs.map((c, i) => `<button onclick="clGo(this.dataset.p)" data-p="${esc(c.path)}" class="${i === v.crumbs.length - 1 ? 'on' : ''}">${esc(i ? c.name : c.name.slice(0, 2))}</button>`).join('<i>›</i>');
  const f = CL.focus && v.entries.find(e => e.path === CL.focus);
  return `<div class="cl-split"><div class="card cl-list"><div class="cl-crumbs">${v.crumbs.length > 1 ? `<button class="cl-up" onclick="clGo(CL.view.crumbs[CL.view.crumbs.length-2].path)">↑</button>` : ''}${crumbs}<span class="sp"></span><b class="mono">${fBytes(v.self.size)}</b></div>
      <div class="cl-why">${v.self.class.why ? clBadge(v.self.class) + ' ' + esc(v.self.class.why) : ''}</div>${clRows(v.entries, '', false)}</div>
    <div class="cl-side"><div class="card cl-tm"><div class="cl-lh">Mapa de «${esc(v.self.name.length > 3 ? v.self.name : v.self.name.slice(0, 2))}» · pulsa una carpeta para entrar</div><div id="clMap" class="cl-map"></div></div>
      <div class="card cl-det">${f ? clDetail(f) : '<div class="fa-empty">Pulsa un elemento para ver qué es y si se puede borrar.</div>'}</div></div></div>`;
}
function clDetail(e){
  const v = CLV[e.class.level || ''] || CLV[''];
  const can = !e.rest && e.class.level !== 'sistema' && !e.class.action && !clProtected(e.path);
  return `<div class="cl-dh"><span class="cl-ic big" style="color:${v[2]}"><i class="ic">${ic(e.dir ? 'folder' : 'file')}</i></span><div><b>${esc(e.name)}</b><small class="mono">${esc(e.path)}</small></div></div>
    <div class="cl-dk"><span>Tamaño</span><b>${fBytes(e.size)}</b></div>${e.dir ? `<div class="cl-dk"><span>Archivos</span><b>${(e.files||0).toLocaleString('es-ES')}</b></div>` : ''}
    <div class="cl-dk"><span>Modificado</span><b>${e.mtime ? new Date(e.mtime * 1000).toLocaleString('es-ES') : '—'}</b></div>
    <div class="cl-dv2">${clBadge(e.class) || '<span class="st st-n"><span>Sin clasificar</span></span>'}<p>${esc(e.class.why || (e.dir ? 'Carpeta sin nada especial. Entra para ver qué ocupa.' : 'Archivo sin nada especial. Bórralo solo si sabes lo que es.'))}</p></div>
    <div class="cl-da">${e.class.action ? `<button class="btn pri sm" onclick="clAction('${e.class.action}')">${CLACT[e.class.action]}</button>` : ''}
      ${can ? `<button class="btn sm ${e.class.level === 'borrar' ? 'pri' : ''}" onclick="clDelete([CL.focus], ${e.class.level === 'borrar' ? 'false' : 'true'})">${e.class.level === 'borrar' ? (e.class.inside ? 'Vaciar' : 'Borrar') : 'Enviar a la papelera'}</button>` : ''}
      <button class="btn sm" onclick="caReveal(CL.focus)"><i class="ic">${ic('folder')}</i>Abrir ubicación</button>
      ${!e.dir && !e.rest ? `<button class="btn sm ghost" onclick="showPage('scanfile');setTimeout(()=>faAnalyze(${JSON.stringify(e.path).replace(/"/g, '&quot;')}),200)">Analizar archivo</button>` : ''}</div>`;
}
function clRecsHTML(){
  const r = CL.recs || [];
  const safe = r.filter(x => x.class.level === 'borrar' && !x.class.action), acts = r.filter(x => x.class.action), care = (CL.top || []).filter(x => x.class.level === 'cuidado' && !x.class.action).slice(0, 30);
  const tot = safe.reduce((a, x) => a + x.size, 0);
  return `<div class="cl-recs"><div class="card cl-list"><div class="cl-rh"><div><b>Se puede borrar sin perder nada · ${fBytes(tot)}</b><small>Temporales, cachés, papeleras de todos los usuarios, volcados de errores… Windows y los programas lo regeneran si hace falta. Lo que esté en uso se queda.</small></div>
      <button class="btn pri" onclick="clDelete(${JSON.stringify(safe.map(x => x.path)).replace(/"/g, '&quot;')}, false)" ${safe.length ? '' : 'disabled'}><i class="ic">${ic('check')}</i>Liberar ${fBytes(tot)}</button></div>${clRows(safe, '', true)}</div>
    ${acts.length ? `<div class="card cl-list"><div class="cl-rh"><div><b>Con la herramienta de Windows</b><small>Esto no se borra a mano: se libera con su opción oficial.</small></div></div>${clRows(acts, '', true)}</div>` : ''}
    ${care.length ? `<div class="card cl-list"><div class="cl-rh"><div><b>Revisa antes · ${fBytes(care.reduce((a, x) => a + x.size, 0))}</b><small>Instaladores viejos en Descargas, imágenes de disco y vídeos enormes. Márcalos si ya no los necesitas: van a la papelera.</small></div></div>${clRows(care, '', true)}</div>` : ''}</div>`;
}
function clQuickHTML(){
  const l = S.items.filter(i => i.category === 'Limpieza');
  return `<div class="card cl-list"><div class="cl-rh"><div><b>Limpieza rápida</b><small>Lo de siempre, sin analizar el disco entero: temporales, papeleras de todos los usuarios, cachés de navegador y de Windows Update. Al terminar se mide lo que se ha liberado de verdad.</small></div>
    <button class="btn pri" onclick="clQuick()" ${l.length ? '' : 'disabled'}>Limpiar todo</button></div>
    ${l.length ? l.map(i => `<div class="cl-row"><label class="cl-ck off"></label><span class="cl-ic" style="color:#12a06b"><i class="ic">${ic('trash')}</i></span><div class="cl-nm"><b>${esc(i.name)}</b><small>${esc(firstLine(i.detail))}</small></div><div class="cl-bar"></div><div class="cl-sz mono">${esc(i.current)}</div><div class="cl-bd">${pill(i.status)}</div></div>`).join('') : '<div class="fa-empty" style="padding:20px">Pulsa «Escanear» en Inicio para medir la basura.</div>'}</div>`;
}
function clQuick(){
  const ids = S.items.filter(i => i.category === 'Limpieza' && i.status !== 'Limpio').map(i => i.id);
  if (!ids.length) return;
  S.busy = true; SC.userClosed = false; scanner(true); render(); caRun(ids).then(() => setTimeout(() => poll(true), 150));
}
async function clGo(p){ CL.path = p; CL.focus = null; const v = await caDiskView(p); if (v && v.ok) CL.view = v.view; clDrawBody(); }
function clClick(p, dir, rest){ if (rest) return; if (CL.tab === 'tree' && dir && CL.focus === p) { clGo(p); return; } CL.focus = p; if (CL.tab === 'tree') clDrawBody(); else { const e = [...(CL.recs||[]), ...(CL.top||[])].find(x => x.path === p); if (e) modal(esc(e.name), clDetail(e), [{t:'Cerrar'}]); } }
function clToggle(p, size, on){ if (on) CL.sel[p] = size; else delete CL.sel[p]; clDrawSel(); }
function clDrawSel(){
  const d = CL.del || {}; const el = $('#clSel');
  if (d.running) { el.innerHTML = `<div class="cl-selbar run"><span class="cl-spin"></span><b>Liberando espacio… ${d.done + 1} de ${d.total}</b><small class="mono">${esc(d.cur || '')}</small><span class="sp"></span><b>${fBytes((d.res || {}).freed || 0)} liberados</b></div>`; return; }
  const k = Object.keys(CL.sel); if (!k.length) { el.innerHTML = ''; return; }
  const tot = Object.values(CL.sel).reduce((a, x) => a + x, 0);
  el.innerHTML = `<div class="cl-selbar"><b>${k.length} seleccionado(s) · ${fBytes(tot)}</b><span class="sp"></span><button class="btn sm ghost" onclick="CL.sel={};clDraw()">Quitar selección</button><button class="btn sm" onclick="clDelete(Object.keys(CL.sel), true)">Enviar a la papelera</button><button class="btn sm danger" onclick="clDelete(Object.keys(CL.sel), false)">Borrar definitivamente</button></div>`;
}
function clDelete(paths, toBin){
  if (!paths || !paths.length) return;
  const all = [...(CL.recs||[]), ...(CL.top||[]), ...((CL.view||{}).entries||[])];
  const tot = paths.reduce((a, p) => a + ((all.find(x => x.path === p) || {}).size || CL.sel[p] || 0), 0);
  const personal = paths.some(p => { const e = all.find(x => x.path === p); return e && ['personal','cuidado',''].includes(e.class.level); });
  modal(toBin ? 'Enviar a la papelera' : 'Borrar', `<p style="margin-top:0">Se van a ${toBin ? 'enviar a la papelera' : '<b>borrar</b>'} <b>${paths.length}</b> elemento(s) · unos <b>${fBytes(tot)}</b>.</p>
    ${toBin ? '<p class="help">Podrás recuperarlos desde la Papelera. El espacio no se libera del todo hasta vaciarla.</p>' : personal ? '<p class="help" style="color:var(--red-ink)"><b>Hay archivos personales o que conviene revisar: se borrarán sin pasar por la papelera.</b></p>' : '<p class="help">Son temporales y cachés: Windows y los programas los regeneran. Lo que esté en uso se queda.</p>'}
    <div class="cl-mlist">${paths.slice(0, 8).map(p => `<code>${esc(p)}</code>`).join('')}${paths.length > 8 ? `<small>y ${paths.length - 8} más</small>` : ''}</div>`,
    [{t:'Cancelar'}, {t: toBin ? 'Enviar a la papelera' : 'Borrar', c:'pri', f: async () => { const m = await caDiskDelete(paths, toBin); if (m) { toast(esc(m)); return; } CL.sel = {}; CL.del = {running:true, done:0, total:paths.length, res:{freed:0}}; clDrawSel(); clWatch(); }}]);
}
async function clDelDone(){
  const r = CL.del.res || {};
  const msg = `Liberados ${fBytes(r.freed || 0)}${CL.del.binned ? ' y ' + fBytes(CL.del.binned) + ' enviados a la papelera' : ''}${r.failed ? ` · ${r.failed} archivo(s) estaban en uso y se han quedado` : ''}${(r.skipped||[]).length ? ` · ${r.skipped.length} no se han tocado (sistema)` : ''}.`;
  toast(esc(msg));
  CL.drives = await caDrives() || CL.drives;
  await clLoad(); clDraw();
}
function clAction(a){
  const txt = {hiber:'Se desactiva la hibernación (powercfg /hibernate off) y Windows borra hiberfil.sys. Perderás la opción «Hibernar» y el «inicio rápido».', dism:'Se ejecuta la limpieza oficial de componentes de Windows (DISM /StartComponentCleanup). Quita versiones antiguas que ya no hacen falta. Tarda entre 5 y 30 minutos.', storage:'Se abre Configuración → Almacenamiento, desde donde Windows borra la instalación anterior (Windows.old).'}[a];
  modal(CLACT[a], `<p style="margin-top:0">${txt}</p>`, [{t:'Cancelar'}, {t:'Continuar', c:'pri', f: async () => { const m = await caDiskAction(a); toast(esc(m)); if (a === 'hiber') { CL.drives = await caDrives(); await clLoad(); clDraw(); } }}]);
}
// mapa de rectángulos (treemap "squarified")
function clTreemap(){
  const box = $('#clMap'); if (!box || !CL.view) return;
  const W = box.clientWidth, H = box.clientHeight; if (!W || !H) return;
  const items = CL.view.entries.filter(e => e.size > 0).slice(0, 60);
  const total = items.reduce((a, e) => a + e.size, 0); if (!total) { box.innerHTML = '<div class="fa-empty">Vacío</div>'; return; }
  const area = W * H, nodes = items.map(e => ({e, a: e.size / total * area})), rects = [];
  let x = 0, y = 0, w = W, h = H, row = [];
  const worst = (r, s) => { const sum = r.reduce((a, n) => a + n.a, 0), mx = Math.max(...r.map(n => n.a)), mn = Math.min(...r.map(n => n.a)); return Math.max(s * s * mx / (sum * sum), sum * sum / (s * s * mn)); };
  const lay = r => { const sum = r.reduce((a, n) => a + n.a, 0); if (w >= h) { const cw = sum / h; let cy = y; r.forEach(n => { const ch = n.a / cw; rects.push([n.e, x, cy, cw, ch]); cy += ch; }); x += cw; w -= cw; } else { const rh = sum / w; let cx = x; r.forEach(n => { const cw = n.a / rh; rects.push([n.e, cx, y, cw, rh]); cx += cw; }); y += rh; h -= rh; } };
  for (const n of nodes) { const s = Math.min(w, h); if (!row.length || worst([...row, n], s) <= worst(row, s)) row.push(n); else { lay(row); row = [n]; } }
  if (row.length) lay(row);
  box.innerHTML = rects.map(([e, rx, ry, rw, rh]) => { const v = CLV[e.class.level || ''] || CLV['']; const lab = rw > 70 && rh > 30;
    return `<div class="cl-tile ${e.dir ? 'dir' : ''} ${CL.focus === e.path ? 'focus' : ''}" data-p="${esc(e.path)}" style="left:${rx}px;top:${ry}px;width:${Math.max(0, rw - 2)}px;height:${Math.max(0, rh - 2)}px;--c:${v[2]}" title="${esc(e.name)} · ${fBytes(e.size)}"
      onclick="${e.rest ? '' : e.dir ? 'clGo(this.dataset.p)' : 'CL.focus=this.dataset.p;clDrawBody()'}">${lab ? `<b>${esc(e.name)}</b><small>${fBytes(e.size)}</small>` : ''}</div>`; }).join('');
}
window.addEventListener('resize', () => { if (S.page === 'clean' && CL.tab === 'tree') clTreemap(); });

/* ====================== Procesos ====================== */""")
