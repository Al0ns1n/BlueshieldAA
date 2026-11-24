# 4.1: anti-ransomware de vuelta, con modo simulacro / contención y salida de la cuarentena
# con lista de comprobación. Sustituye la página y las funciones rw* de la 3.x.

t = doc.t
a = t.index('function ransomPage(){')
b = t.index('\n}\n', a) + 3
doc.t = t[:a] + r'''function ransomPage(){
  return `<div class="page" id="p-ransom"><div class="rw-wrap">
    <div id="rwCt"></div>
    <div class="card rw-hero" id="rwHero"></div>
    <div class="card rw-card"><div><h3>Qué hacer al detectar un ataque</h3><p class="rw-sub">Empieza en simulacro. Cuando hayas comprobado que no da falsas alarmas en tu equipo, pásalo a «Contener».</p></div>
      <div id="rwMode"></div><div id="rwOpts"></div></div>
    <div class="card rw-card">
      <h3>Cómo lo detecta</h3>
      <div class="rw-steps">
        <div><span class="n">1</span><b>Documentos trampa ocultos</b><span>Cinco documentos ocultos de aspecto real (Word, Excel, PDF, texto y una foto) en el Escritorio, Documentos, Imágenes y Descargas de cada usuario, en Documentos públicos y en la raíz de los discos de datos. Nunca en OneDrive, SharePoint, otras nubes, la red, USB ni en el perfil .adm. Sus nombres quedan los primeros y los últimos de la carpeta, que es por donde empieza a cifrar un ransomware.</span></div>
        <div><span class="n">2</span><b>Órdenes que se lanzan antes de cifrar</b><span>Borrar las instantáneas de Windows, desactivar la recuperación o borrar las copias de seguridad. Se cortan siempre (también en simulacro) y, si las ha lanzado un programa que no es de Microsoft, se considera un ataque.</span></div>
        <div><span class="n">3</span><b>Un guardián desde que arranca Windows</b><span>Una tarea programada como SYSTEM revisa los señuelos cada medio segundo y los procesos nuevos cada cuarto de segundo, aunque la ventana esté cerrada. Para averiguar el culpable mira qué programas estaban escribiendo en disco en ese instante.</span></div>
      </div>
    </div>
    <div class="card rw-card"><div class="rw-h"><div><h3>Carpetas protegidas</h3><p class="rw-sub">Se eligen solas y se revisan cada 10 minutos (usuarios o discos nuevos). Puedes añadir otras carpetas locales; las de OneDrive, SharePoint, otras nubes, la red o un USB no se admiten.</p></div>
      <button class="btn" onclick="rwAddFolder()"><i class="ic">${ic('folder')}</i>Añadir carpeta…</button></div>
      <div id="rwFolders"></div></div>
    <div class="card rw-card"><div class="rw-h"><h3>Incidentes</h3><button class="btn sm ghost" onclick="rwShowLog()"><i class="ic">${ic('file')}</i>Registro del guardián</button></div><div id="rwInc"></div></div>
  </div></div>`;
}
''' + t[b:]

t = doc.t
a = t.index('function rwInit(){')
b = t.index('function faAnalyzeFromRansom(p)')
doc.t = t[:a] + r'''function rwInit(){ RW.chkAt = 0; rwLoad(); clearInterval(RW.t); RW.t = setInterval(() => { if (S.page === 'ransom') rwLoad(); else clearInterval(RW.t); }, 3000); }
async function rwLoad(){
  RW.s = await caDecoyStatus();
  const c = RW.s && RW.s.containment;
  if (c && c.active && !c.simulated && Date.now() - (RW.chkAt || 0) > 15000) rwChecks();
  rwRender(); ctBanner(RW.s);
}
async function rwChecks(){ RW.chkAt = Date.now(); RW.chk = await caGuardChecks(!!RW.rev, !!RW.ext); rwRender(); }
function rwAgo(iso){ if (!iso || iso.startsWith('0001')) return ''; const s = Math.max(0, Math.round((Date.now() - new Date(iso)) / 1000)); return s < 60 ? `hace ${s} s` : s < 3600 ? `hace ${Math.round(s / 60)} min` : new Date(iso).toLocaleString('es-ES'); }
function rwWhen(iso){ return new Date(iso).toLocaleString('es-ES', {day:'2-digit', month:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit'}); }
function rwJs(p){ return esc(p).replace(/\\/g, '\\\\').replace(/'/g, "\\'"); }
function rwRender(){
  const s = RW.s; if (!s) return;
  const c = s.containment || {};
  const contained = c.active && !c.simulated;
  const sim = s.mode !== 'contener';
  const open = (s.incidents || []).filter(i => !i.resolved && i.kind !== 'prueba');
  const state = s.portable ? ['off', 'shield', 'Solo en la versión instalada', 'El anti-ransomware necesita un guardián que arranque con Windows como SYSTEM, y eso solo lo tiene BlueShieldAA instalado. La versión portable no deja nada funcionando en el equipo.']
    : contained ? ['bad', 'lock', 'Equipo en modo contención', 'Solo se ejecuta Windows, la red está cortada y los servicios que comparten el equipo están parados. Mira arriba cómo salir.']
    : !s.enabled ? ['off', 'shield', 'Protección desactivada', 'Al activarla se ponen los documentos trampa y arranca el guardián. Empieza en modo simulacro: solo avisa.']
    : s.running ? ['ok', 'shield', sim ? 'Vigilando · modo simulacro' : 'Protegido · modo contención', `${s.decoys} documentos trampa en ${(s.folders || []).length} carpetas · guardián ${s.guardVersion || ''} activo ${rwAgo(s.beat)}`]
    : ['warn', 'alert', 'El guardián no está en marcha', s.task ? 'La tarea programada existe pero el guardián no responde. Pulsa «Reiniciar el guardián».' : 'Falta la tarea programada del guardián. Pulsa «Reiniciar el guardián».'];
  const bad = contained || open.some(i => i.kind === 'ataque' || i.kind === 'orden');
  $('#rwHero').className = 'card rw-hero ' + (bad ? 'bad' : state[0]);
  $('#rwHero').innerHTML = `<span class="rw-hi"><i class="ic">${ic(bad ? 'alert' : state[1])}</i></span>
    <div class="rw-ht"><b>${!contained && open.length ? `${open.length} aviso(s) sin revisar` : state[2]}</b><span>${!contained && open.length ? 'Revisa abajo qué ha pasado.' : esc(state[3])}</span></div>
    <div class="rw-ha">${s.portable || contained ? '' : s.enabled
      ? `${s.running ? `<button class="btn" ${RW.busy ? 'disabled' : ''} onclick="rwTest()"><i class="ic">${ic('target')}</i>Probar ahora</button>` : `<button class="btn pri" ${RW.busy ? 'disabled' : ''} onclick="rwEnable(true)"><i class="ic">${ic('refresh')}</i>Reiniciar el guardián</button>`}
         <button class="btn ghost" ${RW.busy ? 'disabled' : ''} onclick="rwEnable(false)">Desactivar</button>`
      : `<button class="btn pri" ${RW.busy ? 'disabled' : ''} onclick="rwEnable(true)"><i class="ic">${ic('shield')}</i>Activar en simulacro</button>`}</div>`;
  $('#rwMode').innerHTML = `<div class="rw-modes">
    <button class="rw-m ${sim ? 'on' : ''}" ${contained ? 'disabled' : ''} onclick="rwSetMode('simulacro')"><b><i class="ic">${ic('bell')}</i>Simulacro</b><span>Solo avisa en pantalla y apunta lo que habría hecho. No detiene nada ni corta la red.</span></button>
    <button class="rw-m ${!sim ? 'on' : ''} danger" ${contained ? 'disabled' : ''} onclick="rwSetMode('contener')"><b><i class="ic">${ic('lock')}</i>Contener</b><span>Congela al culpable y pone el equipo en cuarentena hasta que lo liberes desde aquí. Se mantiene aunque reinicies.</span></button></div>`;
  const sw = (k, t, d) => `<div class="sw ${s[k] ? 'on' : ''} ${sim ? 'dim' : ''}" onclick="rwOpt('${k}')"><div class="track"></div><div><b>${t}</b><small>${d}</small></div></div>`;
  $('#rwOpts').innerHTML = `<p class="rw-sub" style="margin:0">${sim ? 'En simulacro estas opciones solo se apuntan («habría cerrado…»). Se aplican al pasar a «Contener».' : 'En la contención, además de congelar y poner en cuarentena el programa culpable:'}</p>`
    + sw('lockdown', 'Dejar ejecutar solo Windows', 'Se cierra al momento todo lo que no esté firmado por Microsoft (salvo BlueShieldAA, tu antivirus y los controladores de Intel, AMD, NVIDIA o Realtek), y también PowerShell, cmd, wscript, mshta, vssadmin, wmic, bcdedit y otras herramientas que usa el ransomware. El escritorio, el Explorador, Office y Defender siguen funcionando.')
    + sw('isolate', 'Cortar la red', 'Bloquea toda la red con el cortafuegos de Windows (se guarda antes tu configuración para dejarla tal cual). Así no cifra carpetas compartidas ni recibe órdenes de fuera.')
    + sw('stopSvc', 'Parar los servicios que comparten el equipo', 'Compartir archivos (SMB), Escritorio remoto, WinRM, Registro remoto, SSH… y los servicios que no son de Microsoft. Se apunta cómo estaban para devolverlos igual.');
  const custom = (s.custom || []).map(x => x.toLowerCase());
  const fl = s.folders || [];
  $('#rwFolders').innerHTML = (s.errors || []).map(e => `<div class="rw-err"><i class="ic">${ic('alert')}</i>${esc(e)}</div>`).join('') + (fl.length
    ? `<div class="rw-fl">${fl.map(f => `<div class="rw-f"><i class="ic">${ic('folder')}</i><span>${esc(f.path)}</span><em>${f.n} señuelo${f.n === 1 ? '' : 's'}</em>${custom.includes(f.path.toLowerCase()) ? `<button class="btn sm ghost" onclick="rwRemoveFolder('${rwJs(f.path)}')">Quitar</button>` : ''}</div>`).join('')}</div>`
    : `<div class="rw-empty">${s.enabled ? 'Poniendo los señuelos…' : 'Se mostrarán al activar la protección.'}</div>`);
  const inc = s.incidents || [];
  const KIND = {ataque: ['bad', 'Posible ransomware'], orden: ['bad', 'Orden de ransomware cortada'], aviso: ['warn', 'Documento trampa borrado'], prueba: ['test', 'Prueba superada']};
  $('#rwInc').innerHTML = inc.length ? `<div class="rw-il">${inc.map(i => {
      const k = KIND[i.kind] || ['warn', i.kind];
      const cls = i.resolved ? 'done' : k[0];
      const cul = i.culprits || [];
      const what = i.kind === 'ataque' && i.simulated ? 'Posible ransomware (simulacro)' : k[1];
      return `<div class="rw-i ${cls}"><div class="rw-it"><b>${what}</b><span>${new Date(i.when).toLocaleString('es-ES')}${i.ms ? ` · ${i.ms} ms` : ''}</span>${i.resolved ? '<em>resuelto</em>' : ''}</div>
        <p class="rw-why">${esc(i.reason)}</p>
        ${i.kind === 'aviso' || i.kind === 'orden' ? '' : `<div class="rw-id">
          <div><span>Culpable</span><b>${cul.length ? cul.map(x => esc(x.name) + ' (PID ' + x.pid + ')').join(', ') : 'no identificado'}</b></div>
          <div><span>${i.simulated ? 'Habría cerrado' : 'Cuarentena'}</span><b>${i.simulated ? (i.wouldKill || []).length + ' programas' : cul.filter(x => x.quarantined).length + ' archivo(s)'}</b></div>
          <div><span>${i.simulated ? 'Habría parado' : 'Red'}</span><b>${i.simulated ? (i.wouldStop || []).length + ' servicios' : i.isolated ? 'cortada' : 'sin cambios'}</b></div>
          <div><span>Modo</span><b>${i.simulated ? 'solo aviso' : 'contención'}</b></div>
        </div>`}
        ${cul.map(x => `<div class="rw-cul"><code class="rw-path">${esc(x.path || x.name)}</code><small>${esc(x.why)}</small></div>`).join('')}
        <details><summary>Detalles</summary>${(i.files || []).map(f => `<code class="rw-path">${esc(f)}</code>`).join('')}${(i.newNames || []).length ? `<p>Renombrados como: ${i.newNames.map(esc).join(', ')}</p>` : ''}
          ${(i.wouldKill || []).length ? `<p><b>Habría cerrado:</b></p>${i.wouldKill.map(x => `<code class="rw-path">${esc(x)}</code>`).join('')}` : ''}
          ${(i.wouldStop || []).length ? `<p><b>Habría parado:</b> ${i.wouldStop.map(esc).join(', ')}</p>` : ''}</details>
        ${!i.resolved && i.kind !== 'prueba' ? `<div class="rw-ia"><button class="btn ghost" onclick="rwResolve('${esc(i.id)}')">Marcar como revisado</button></div>` : ''}
      </div>`; }).join('')}</div>`
    : `<div class="rw-empty">Ningún incidente. ${s.enabled ? 'Pulsa «Probar ahora» para comprobar que el guardián reacciona.' : ''}</div>`;
  ctRender(s);
}
function ctRender(s){
  const c = s.containment || {}, el = $('#rwCt'); if (!el) return;
  if (!c.active || c.simulated) { el.innerHTML = ''; return; }
  const chk = RW.chk && RW.chk.active ? RW.chk.checks : null;
  const sc = s.scan || {};
  const row = x => {
    let extra = '';
    if (x.id === 'analisis') extra = `<div class="ct-act">${sc.running ? `<span class="ct-spin"></span><span>Analizando con Microsoft Defender… (desde ${new Date(sc.start).toLocaleTimeString('es-ES')})</span>` : `<button class="btn sm pri" onclick="rwScan()"><i class="ic">${ic('search')}</i>Análisis completo con Defender</button>`}
        <label class="ct-ck"><input type="checkbox" ${RW.ext ? 'checked' : ''} onchange="RW.ext=this.checked; rwChecks()">Lo he analizado con otro antivirus</label></div>`;
    if (x.id === 'inicio' && (x.list || []).length) extra = `<div class="ct-list">${x.list.map(l => `<code class="rw-path">${esc(l)}</code>`).join('')}</div>
        <label class="ct-ck"><input type="checkbox" ${RW.rev ? 'checked' : ''} onchange="RW.rev=this.checked; rwChecks()">Lo he revisado y no es del ataque</label>`;
    return `<div class="ct-row ${x.ok ? 'ok' : ''}"><span class="ct-dot"><i class="ic">${ic(x.ok ? 'check' : 'x')}</i></span><div><b>${esc(x.title)}</b><span>${esc(x.detail)}</span>${extra}</div></div>`;
  };
  const cul = c.culprits || [];
  el.innerHTML = `<div class="card ct-card">
    <div class="ct-top"><span class="ct-ic"><i class="ic">${ic('lock')}</i></span><div><b>Este equipo está en cuarentena</b><span>Desde ${rwWhen(c.since)} · ${esc(c.reason)}</span></div></div>
    <div class="ct-grid">
      <div><span>Culpable</span><b>${cul.length ? cul.map(x => esc(x.name)).join(', ') : 'no identificado'}</b></div>
      <div><span>Red</span><b>${c.isolated ? 'cortada' : 'sin cortar'}</b></div>
      <div><span>Servicios parados</span><b>${(c.services || []).length}</b></div>
      <div><span>Programas cerrados</span><b>${(c.killed || []).length}</b></div>
    </div>
    ${(c.errors || []).map(e => `<div class="rw-err"><i class="ic">${ic('alert')}</i>${esc(e)}</div>`).join('')}
    <div><h4 class="ct-h">Para salir de la cuarentena</h4>
    <div class="ct-rows">${chk ? chk.map(row).join('') : '<div class="rw-empty">Comprobando…</div>'}
      <div class="ct-row opt"><span class="ct-dot"><i class="ic">${ic('info')}</i></span><div><b>Recomendado: análisis sin conexión de Microsoft Defender</b><span>Reinicia el equipo y lo analiza antes de que arranque Windows (unos 15 minutos). Encuentra lo que se esconde mientras Windows está en marcha. Al volver, el equipo sigue en cuarentena.</span><div class="ct-act"><button class="btn sm" onclick="rwOffline()">Programar y reiniciar…</button></div></div></div>
    </div></div>
    <div class="ct-note"><i class="ic">${ic('info')}</i><span>Ninguna herramienta puede garantizar al 100 % que el equipo está limpio. Si el ransomware llegó a cifrar archivos de verdad, lo más seguro es <b>reinstalar Windows</b> y recuperar los documentos de una copia anterior al ataque.</span></div>
    <div class="ct-go"><input id="ctConfirm" placeholder="Escribe LIBERAR" autocomplete="off" oninput="ctGoState()"><button class="btn pri" id="ctGo" disabled onclick="rwRelease()"><i class="ic">${ic('check')}</i>Liberar el equipo</button></div>
    <details class="ct-more"><summary>Qué se ha hecho y cómo desbloquearlo si la ventana no abre</summary>
      ${(c.services || []).length ? `<p><b>Servicios parados:</b> ${c.services.map(x => esc(x.display || x.name)).join(', ')}</p>` : ''}
      ${(c.killed || []).length ? `<p><b>Programas cerrados (últimos):</b></p>${c.killed.slice(-40).reverse().map(x => `<code class="rw-path">${esc(x)}</code>`).join('')}` : ''}
      <p>Si BlueShieldAA no abriera, ejecuta como administrador <b>desbloquear.cmd</b> de la carpeta del programa: quita los bloqueos sin comprobar nada. <button class="lnk" onclick="caGuardOpenEscape()">Mostrar el archivo</button></p></details>
  </div>`;
  ctGoState();
}
function ctGoState(){ const i = $('#ctConfirm'), b = $('#ctGo'); if (!i || !b) return; b.disabled = !(RW.chk && RW.chk.can) || i.value.trim().toUpperCase() !== 'LIBERAR'; }
async function rwRelease(){
  const i = $('#ctConfirm'); const b = $('#ctGo'); b.disabled = true; b.textContent = 'Liberando…';
  const m = await caGuardRelease(i.value, !!RW.rev, !!RW.ext);
  if (m && !m.startsWith('Liberado con avisos')) { toast(esc(m)); ctGoState(); return; }
  modal('Equipo liberado', `<p style="margin-top:0">${m ? esc(m) : 'Se ha devuelto la red, los servicios y la ejecución normal de programas.'}</p><p>El guardián sigue vigilando con documentos trampa nuevos. Revisa qué entró (Analizar archivo, Cambios) y cambia las contraseñas que se usaran en este equipo.</p>`, [{t:'Entendido', c:'pri'}]);
  RW.chk = null; rwLoad();
}
async function rwScan(){ const m = await caGuardScan(); toast(m ? esc(m) : 'Análisis completo en marcha. Puede tardar más de una hora; puedes cerrar esta ventana.'); rwLoad(); }
function rwOffline(){
  modal('Análisis sin conexión', '<p style="margin-top:0">Microsoft Defender programará el análisis y <b>el equipo se reiniciará en un momento</b>. Guarda lo que tengas abierto.</p><p>El equipo seguirá en cuarentena al volver.</p>',
    [{t:'Cancelar'}, {t:'Reiniciar y analizar', c:'pri', f: async () => { const m = await caGuardOffline(); toast(m ? esc(m) : 'Análisis programado: el equipo se reiniciará.'); }}]);
}
async function rwEnable(on){
  if (!on) {
    modal('Desactivar la protección', '<p style="margin-top:0">Se quitarán todos los documentos trampa y se borrará la tarea del guardián. El equipo quedará sin esta protección contra ransomware.</p>',
      [{t:'Cancelar'}, {t:'Desactivar', c:'pri', f: async () => { RW.busy = true; rwRender(); const m = await caDecoyEnable(false); RW.busy = false; toast(m ? esc(m) : 'Protección desactivada y señuelos quitados.'); rwLoad(); }}]);
    return;
  }
  RW.busy = true; rwRender();
  const m = await caDecoyEnable(true);
  RW.busy = false;
  toast(m ? esc(m) : 'Guardián en marcha: poniendo los documentos trampa…');
  setTimeout(rwLoad, 2500);
}
function rwSetMode(m){
  const s = RW.s; if (!s || s.mode === m) return;
  if (m === 'simulacro') { caGuardMode(m).then(() => { toast('Modo simulacro: solo avisará.'); rwLoad(); }); return; }
  modal('Pasar a modo contención', `<p style="margin-top:0">Si el guardián detecta un ataque, <b>este equipo</b> quedará en cuarentena hasta que lo liberes desde aquí:</p>
    <ul class="ct-ul"><li>Se congela y se pone en cuarentena el programa culpable.</li>${s.lockdown ? '<li>Solo podrán ejecutarse programas de Windows: se cerrará todo lo demás, también lo que tengas abierto sin guardar.</li>' : ''}${s.isolate ? '<li>Se corta toda la red (también Internet).</li>' : ''}${s.stopSvc ? '<li>Se paran la compartición de archivos, el Escritorio remoto y los servicios que no son de Microsoft.</li>' : ''}<li>Se mantiene aunque reinicies.</li></ul>
    <p>Solo afecta a este equipo. Si algo fallara, <b>desbloquear.cmd</b> (en la carpeta del programa, como administrador) lo quita todo.</p>
    <p class="rw-sub">Recomendado: déjalo antes unos días en simulacro y revisa que no salen avisos falsos.</p>`,
    [{t:'Cancelar'}, {t:'Pasar a contener', c:'pri', f: async () => { const r = await caGuardMode('contener'); toast(r ? esc(r) : 'Modo contención activado.'); rwLoad(); }}]);
}
async function rwOpt(k){ const s = RW.s; if (!s) return; s[k] = !s[k]; rwRender(); const m = await caDecoyOptions(!!s.isolate, !!s.stopSvc, !!s.lockdown); if (m) toast(esc(m)); }
function rwAddFolder(){
  modal('Añadir una carpeta', `<p style="margin-top:0">Se pondrán 5 documentos trampa ocultos en la carpeta que elijas.</p>
    <p>Tiene que ser una carpeta <b>local de este equipo</b>. Las de OneDrive, SharePoint, otras nubes (Google Drive, Dropbox…), unidades de red o USB se rechazan, para que los señuelos nunca salgan del equipo ni lleguen a otros.</p>`,
    [{t:'Cancelar'}, {t:'Elegir carpeta…', c:'pri', f: rwAddFolderGo}]);
}
async function rwAddFolderGo(){ const p = await caDecoyAddFolder(); if (p && p.startsWith('ERROR:')) { modal('Carpeta no admitida', `<p style="margin-top:0">${esc(p.slice(6))}</p>`, [{t:'Entendido', c:'pri'}]); return; } if (p) { toast('Carpeta añadida: el guardián pondrá los señuelos en unos segundos.'); setTimeout(rwLoad, 2500); } }
async function rwRemoveFolder(p){ await caDecoyRemoveFolder(p); toast('Carpeta quitada.'); setTimeout(rwLoad, 2500); }
function rwTest(){
  modal('Probar la protección', `<p style="margin-top:0">El guardián añadirá un salto de línea a <b>un solo documento trampa</b> de texto de una carpeta local y comprobará que lo detecta.</p>
    <ul class="ct-ul"><li>Siempre es un simulacro, aunque estés en modo «Contener»: no se cierra nada ni se corta la red.</li><li>Verás un aviso en pantalla y aquí, lo que <b>habría hecho</b>: qué programas habría cerrado y qué servicios habría parado.</li><li>El señuelo se sustituye por uno nuevo.</li></ul>`, [{t:'Cancelar'}, {t:'Probar', c:'pri', f: rwTestGo}]);
}
async function rwTestGo(){
  const m = await caDecoyTest();
  if (m) { toast(esc(m)); return; }
  toast('Prueba en marcha: el guardián debería avisarte en un par de segundos.');
  setTimeout(rwLoad, 3000);
}
async function rwResolve(id){ await caDecoyResolve(id); toast('Marcado como revisado.'); setTimeout(rwLoad, 800); }
async function rwShowLog(){ const l = await caGuardLog(); modal('Registro del guardián', `<pre class="ct-log">${esc(l || 'Aún no hay nada.')}</pre>`, [{t:'Cerrar', c:'pri'}]); }
// Aviso fijo en cualquier página mientras el equipo esté en contención
function ctBanner(s){
  let b = $('#ctBanner');
  const on = S.page !== 'ransom' && s && s.containment && s.containment.active && !s.containment.simulated;
  if (!on) { if (b) b.remove(); return; }
  if (!b) { b = document.createElement('div'); b.id = 'ctBanner'; b.onclick = () => showPage('ransom'); document.body.appendChild(b); }
  b.innerHTML = `<i class="ic">${ic('lock')}</i><b>Equipo en cuarentena por posible ransomware</b><span>Solo se ejecuta Windows y no hay red. Pulsa para ver cómo liberarlo.</span>`;
}
async function ctPoll(){ try { if (typeof caDecoyStatus === 'function' && S.page !== 'ransom') ctBanner(await caDecoyStatus()); } catch (e) {} }
setTimeout(ctPoll, 2000); setInterval(ctPoll, 15000);
''' + t[b:]

rep("ransom:'Archivos trampa ocultos y un guardián que detiene el cifrado en sus primeros segundos.'",
    "ransom:'Documentos trampa, órdenes previas al cifrado y un modo contención que pone el equipo en cuarentena.'")
rep("  if (p === 'ransom') rwInit();", "  if (p === 'ransom') rwInit(); else setTimeout(ctPoll, 50);")
