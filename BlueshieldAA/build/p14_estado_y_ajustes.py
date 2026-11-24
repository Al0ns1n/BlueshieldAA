# 4.2: lo que se ve siempre al día y avisos del menú que se quitan al entrar; Ajustes para
# uso doméstico (fuera lo de empresa, webs, servidores, npm…).

t = doc.t
a = t.index('function updateBadges(){')
b = t.index('function renderActivity(){')
doc.t = t[:a] + r'''// Avisos del menú: el número son los avisos que aún no has visto. Al entrar en el apartado se
// dan por vistos y el punto rojo desaparece; si aparece uno nuevo (o cambia de estado) vuelve.
const SEEN = (() => { try { return JSON.parse(localStorage.getItem('bsSeen') || '{}'); } catch (e) { return {}; } })();
function pendIds(p){
  const cats = PAGE_CATS[p] || [];
  return S.items.filter(i => cats.includes(i.category) && (p === 'changes' ? i.action === 'acceptchange' && PENDING.includes(i.status)
    : p === 'events' ? ['Vulnerable','Revisar'].includes(i.status) : (isExp(i) || PENDING.includes(i.status)))).map(i => i.id + '|' + i.status);
}
function markSeen(p){
  const ids = pendIds(p); if (!ids.length) return;
  let ch = false; ids.forEach(k => { if (!SEEN[k]) { SEEN[k] = Date.now(); ch = true; } });
  if (!ch) return;
  const keys = Object.keys(SEEN); if (keys.length > 800) keys.sort((x, y) => SEEN[x] - SEEN[y]).slice(0, keys.length - 600).forEach(k => delete SEEN[k]);
  try { localStorage.setItem('bsSeen', JSON.stringify(SEEN)); } catch (e) {}
}
const unseen = p => pendIds(p).filter(k => !SEEN[k]).length;
function updateBadges(){
  const all = S.items, ex = all.filter(isExp).length;
  if (S.page && PAGE_CATS[S.page]) markSeen(S.page);
  const setB = (id, show, txt) => { const el = $(id); if (!el) return; el.style.display = show ? '' : 'none'; if (show) el.textContent = txt; };
  const nu = unseen('updates'), np = unseen('protect'), nn = unseen('net'), nch = unseen('changes'), ne = unseen('events');
  setB('#b-clean', false, '');
  setB('#b-updates', nu, nu); setB('#b-protect', np, np); setB('#b-net', nn, nn); setB('#b-changes', nch, nch); setB('#b-events', ne, ne);
  setB('#b-protgrp', np + nch, np + nch); setB('#b-netgrp', nn, nn); setB('#b-evgrp', ne, ne);
  $('#bellDot').style.display = ex ? 'block' : 'none';
  $('#bell').title = ex ? `${ex} amenaza(s) activa(s)` : 'Sin amenazas activas';
}
''' + t[b:]

# Al terminar una tarea (o al llegar datos nuevos del segundo plano) se repinta lo que se ve
rep("    if (wasBusy && !S.busy) { loadActivity(); loadScoreTrend(); caDisk().then(d => { DISK = d; render(); }); if (S.page === 'history') loadHistory(); }",
    """    if (wasBusy && !S.busy) { loadActivity(); loadScoreTrend(); caDisk().then(d => { DISK = d; render(); }); if (S.page === 'history') loadHistory();
      if (S.page === 'clean' && typeof clLoad === 'function') { caDrives().then(d => { CL.drives = d || CL.drives; }); clLoad().then(clDraw); }
      if (S.page === 'apps' && typeof apLoad === 'function') apLoad(); }
    else if (changed && S.page === 'clean' && typeof clDraw === 'function' && $('#clTabs')) { clDrawTabs(); if (CL.tab === 'quick') clDrawBody(); }
    else if (changed && !S.busy && S.page === 'apps' && typeof apLoad === 'function') apLoad();
    else if (changed && !S.busy && S.page === 'hw' && typeof hwRender === 'function' && HW.tab === 'comp') hwRender();""")

# ---- Ajustes: solo lo que usa una persona en casa ----
t = doc.t
a = t.index('      <div class="card field"><h3>Bases de vulnerabilidades</h3>')
b = t.index('      <div class="card"><h3>Copias de seguridad</h3>')
t = t[:a] + t[b:]
a = t.index('      <div class="card"><h3>Proyectos npm a auditar</h3>')
b = t.index('      <div class="card"><h3>Avisos ocultos</h3>')
t = t[:a] + t[b:]
a = t.index('        <div class="kvline" style="margin-top:12px"><button class="btn sm" onclick="caOpenPanel()">')
b = t.index('</div>', t.index('</span>', a)) + len('</div>')
t = t[:a] + t[b:]
doc.t = t
rep('''        <div class="sw" data-k="pip"><div class="track"></div><div><b>Paquetes de Python (pip)</b><small>Comprueba vulnerabilidades conocidas en OSV.dev.</small></div></div>
        <div class="sw" data-k="scout"><div class="track"></div><div><b>Imágenes Docker con Docker Scout</b><small>Más lento. Requiere haber iniciado sesión en Docker Desktop.</small></div></div>
''', '')
rep('<button class="btn pri" onclick="compliance()">Informe de cumplimiento (NIS2 · ENS · ISO 27001)</button>\n        ', '')
rep("  ['wu','pip','scout','restore','secrets'].forEach(k => $(`.sw[data-k=\"${k}\"]`).classList.toggle('on', !!S.init.settings[k]));\n  cveInit();\n  renderProjects(S.init.projects);\n",
    "  ['wu','restore','secrets'].forEach(k => $(`.sw[data-k=\"${k}\"]`).classList.toggle('on', !!S.init.settings[k]));\n")
rep("$('#updURL').value = S.init.updateURL || ''; renderLists();", "renderLists();")
rep("  renderServer(S.init.server || {}); $('.sw[data-srv=\"enabled\"]').onclick = e => e.currentTarget.classList.toggle('on');\n", "")
rep("  $('#newDomain').addEventListener('keydown', e => { if (e.key === 'Enter') addDomain(); });\n", "")
rep("  renderSimpleList('#domains', S.domains, i => { S.domains.splice(i, 1); saveLists(); renderLists(); });\n", "")
rep("function saveLists(){ caSaveLists(S.domains, S.backups, $('#updURL').value); }", "function saveLists(){ caSaveLists(S.domains, S.backups, S.init.updateURL || ''); }")
doc.t = doc.t.replace("$('#updState').textContent =", "($('#updState') || {}).textContent =")
rep("  const g = k => $(`.sw[data-k=\"${k}\"]`).classList.contains('on');", "  const g = k => { const e = $(`.sw[data-k=\"${k}\"]`); return e ? e.classList.contains('on') : !!(S.init.settings || {})[k]; };")
rep("settings:'Qué se analiza, tus webs, servidores, apariencia e informes.'", "settings:'Qué se analiza, apariencia, copias de seguridad e informes.'")
rep("net:'Puertos abiertos, accesos remotos, intentos de intrusión, tus webs y tus servidores.'", "net:'Puertos abiertos, accesos remotos e intentos de intrusión.'")
rep('<div class="d" id="kNetD">puertos, intrusiones, webs</div>', '<div class="d" id="kNetD">puertos e intrusiones</div>')
rep("<small>Revisa Escritorio, Documentos, Descargas, OneDrive y tus proyectos. Nada sale del equipo.</small>", "<small>Revisa Escritorio, Documentos, Descargas y OneDrive. Nada sale del equipo.</small>")
rep("S.init.admin ? 'Administrador de TI' : 'Sin permisos de administrador'", "S.init.admin ? 'Administrador' : 'Sin permisos de administrador'")
doc.t = doc.t.replace('ni a la red de la empresa', 'ni a tu red local')
