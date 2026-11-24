# Analizar archivo → "Probar en un entorno aislado" (Windows Sandbox): como ANY.RUN pero en el
# propio equipo y sin red. Capturas en directo, árbol de procesos, archivos, inicio automático,
# documentos señuelo y veredicto combinado con el análisis estático.
rep("""      <div class="fa-acts">
        <button class="btn ${r.verdict === 'Sin señales de peligro' ? '' : 'pri danger-pri'}" onclick="faIsolate()">""",
    """      <div id="sbBox" class="fa-sb"></div>
      <div class="fa-acts">
        <button class="btn ${r.verdict === 'Sin señales de peligro' ? '' : 'pri danger-pri'}" onclick="faIsolate()">""")
rep("""      FA.r = null; faLoadQ();
    }}]);
}""", """      FA.r = null; faLoadQ();
    }}]);
}
/* ---------- entorno aislado (Windows Sandbox) ---------- */
const SB = {id:null, path:'', timer:0, shots:{}, order:[], cur:null, pinned:false, status:null, secs:60, poll:null, lastState:''};
const SB_STEPS = [['arrancando','Arrancando Windows Sandbox (la primera vez puede tardar un par de minutos)'], ['preparando','Preparando el entorno y los documentos señuelo'], ['observando','Abriendo el archivo con doble clic y observando'], ['recogiendo','Recogiendo resultados y cerrando el entorno'], ['terminado','Terminado']];
const SBV = {'Limpio':['ok','check','Sin comportamiento malicioso'], 'Sospechoso':['warn','alert','Comportamiento sospechoso'], 'Peligroso':['bad','alert','Comportamiento de malware'], 'No concluyente':['info','info','No concluyente']};
async function sbInit(){
  const box = $('#sbBox'); if (!box || !FA.r) return;
  if (SB.id && SB.path === FA.r.path) { SB.lastState = ''; sbDraw(); return; }
  clearInterval(SB.timer); Object.assign(SB, {id:null, poll:null, shots:{}, order:[], cur:null, pinned:false, lastState:''});
  box.innerHTML = `<div class="sb-card"><div class="sb-h"><span class="sb-ic"><i class="ic">${ic('target')}</i></span><div><b>Probar en un entorno aislado</b><span>Comprobando si Windows Sandbox está disponible…</span></div></div></div>`;
  try { SB.status = await caSbStatus(); } catch (e) { SB.status = {reason:'No se ha podido comprobar.'}; }
  sbDraw();
}
function sbHead(sub){ return `<div class="sb-h"><span class="sb-ic"><i class="ic">${ic('target')}</i></span><div><b>Probar en un entorno aislado</b><span>${sub}</span></div></div>`; }
function sbViewer(){
  const cur = SB.cur && SB.shots[SB.cur];
  return `<div class="sb-view">${cur && cur !== '…' ? `<img id="sbImg" src="${cur}" alt="">` : '<div class="sb-noimg" id="sbImg0">Las capturas de la pantalla del entorno aparecerán aquí</div>'}</div>
    <div class="sb-thumbs" id="sbThumbs">${SB.order.map(n => sbThumb(n)).join('')}</div>`;
}
function sbThumb(n){ const s = parseInt(n.replace(/\\D/g, ''), 10) * 4; return `<button class="sb-th ${n === SB.cur ? 'on' : ''}" data-n="${n}" onclick="sbPick('${n}')"><img src="${SB.shots[n]}" alt=""><span>${s} s</span></button>`; }
function sbPick(n){ SB.cur = n; SB.pinned = true; const v = $('#sbBox .sb-view'); if (v) v.innerHTML = `<img id="sbImg" src="${SB.shots[n]}" alt="">`; document.querySelectorAll('#sbThumbs .sb-th').forEach(b => b.classList.toggle('on', b.dataset.n === n)); }
function sbProgHTML(){
  const p = SB.poll || {}; const idx = SB_STEPS.findIndex(s => s[0] === p.state);
  const pct = p.state === 'observando' ? Math.min(95, 25 + 65 * Math.min(1, (SB.obsSecs||0) / (p.total||60))) : [5, 15, 25, 95, 100][Math.max(0, idx)];
  return `<ul class="sb-steps">${SB_STEPS.slice(0, 4).map((s, k) => `<li class="${k < idx ? 'd' : k === idx ? 'on' : ''}">${s[1]}${k === 2 && p.state === 'observando' ? ` · ${SB.obsSecs||0} de ${p.total} s` : ''}</li>`).join('')}</ul>
    <div class="sb-bar"><i style="width:${pct}%"></i></div>`;
}
function sbDraw(){
  const box = $('#sbBox'); if (!box) return;
  const st = SB.status || {}, p = SB.poll;
  if (!p) {
    const info = `<ul class="sb-points"><li><b>Sin red:</b> el archivo no puede conectarse a Internet ni a la red de la empresa.</li><li><b>Desechable:</b> al cerrarse, Windows borra el entorno entero. En tu equipo no queda nada.</li><li><b>Solo aquí:</b> no afecta a otros equipos ni usuarios. Se graban capturas, procesos, archivos creados, inicio automático y unos documentos señuelo por si cifra (ransomware).</li></ul>`;
    if (st.enabled) box.innerHTML = `<div class="sb-card">${sbHead('Como ANY.RUN, pero en tu equipo: Windows Sandbox abre el archivo en una máquina desechable y se graba lo que hace.')}${info}
      <div class="sb-go"><span>Observar durante</span><div class="seg" id="sbSecs">${[30, 60, 120].map(s => `<button class="${SB.secs === s ? 'on' : ''}" onclick="SB.secs=${s};sbDraw()">${s} s</button>`).join('')}</div><span class="sp"></span>
        <button class="btn pri" onclick="sbStart()"><i class="ic">${ic('target')}</i>Abrir en el entorno aislado</button></div></div>`;
    else box.innerHTML = `<div class="sb-card">${sbHead(esc(st.reason || 'Windows Sandbox no está disponible en este equipo.'))}${st.available ? info : ''}
      ${st.canEnable ? `<div class="sb-go"><span class="sp"></span><button class="btn" onclick="sbEnable()"><i class="ic">${ic('bolt')}</i>Activar Windows Sandbox</button></div>` : ''}</div>`;
    return;
  }
  if (p.state !== SB.lastState) {
    SB.lastState = p.state;
    if (p.state === 'terminado' && p.result) { box.innerHTML = sbResultHTML(p.result); return; }
    if (p.state === 'error') { box.innerHTML = `<div class="sb-card">${sbHead('No se ha podido completar')}<div class="lk-res warn" style="margin:0"><i class="ic">${ic('alert')}</i><div><b>${esc(p.err || 'Error')}</b></div></div>${SB.order.length ? sbViewer() : ''}<div class="sb-go"><span class="sp"></span><button class="btn" onclick="SB.id=null;SB.poll=null;sbDraw()">Volver a intentarlo</button></div></div>`; return; }
    box.innerHTML = `<div class="sb-card run">${sbHead('El archivo se está abriendo en Windows Sandbox. Puedes seguir usando el programa mientras tanto.')}
      <div id="sbProg">${sbProgHTML()}</div>${sbViewer()}<div class="sb-go"><span class="sp"></span><button class="btn sm" onclick="caSbStop(SB.id)">Cancelar</button></div></div>`;
    return;
  }
  const pr = $('#sbProg'); if (pr) pr.innerHTML = sbProgHTML();
}
function sbAddShot(n){
  SB.order.push(n); SB.order.sort();
  const th = $('#sbThumbs'); if (th) th.insertAdjacentHTML('beforeend', sbThumb(n));
  if (!SB.pinned) { SB.cur = n; const v = $('#sbBox .sb-view'); if (v) v.innerHTML = `<img id="sbImg" src="${SB.shots[n]}" alt="">`; document.querySelectorAll('#sbThumbs .sb-th').forEach(b => b.classList.toggle('on', b.dataset.n === n)); }
}
async function sbStart(){
  if (!FA.r) return;
  const r = await caSbRun(FA.r.path, SB.secs);
  if (!r || r.startsWith('ERROR:')) { toast(esc((r || 'ERROR:No se pudo arrancar').slice(6))); return; }
  Object.assign(SB, {id:r, path:FA.r.path, poll:{state:'arrancando', total:SB.secs, shots:[]}, shots:{}, order:[], cur:null, pinned:false, lastState:'', obsSecs:0, obsT0:0});
  sbDraw(); clearInterval(SB.timer); SB.timer = setInterval(sbTick, 1500);
}
async function sbTick(){
  if (!SB.id) return;
  let p; try { p = await caSbPoll(SB.id); } catch (e) { return; }
  if (p.state === 'observando') { if (!SB.obsT0) SB.obsT0 = Date.now(); SB.obsSecs = Math.min(p.total, Math.round((Date.now() - SB.obsT0) / 1000)); }
  SB.poll = p;
  for (const n of p.shots || []) if (!SB.shots[n]) { SB.shots[n] = '…'; caSbShot(SB.id, n).then(u => { if (u) { SB.shots[n] = u; sbAddShot(n); } }); }
  if (p.state === 'terminado' || p.state === 'error') {
    clearInterval(SB.timer);
    if (p.final) { FA.r = p.final; faRender(); return; }
  }
  sbDraw();
}
async function sbEnable(){
  modal('Activar Windows Sandbox', `<p style="margin-top:0">Se activa la característica de Windows «Espacio aislado de Windows» en <b>este equipo</b>. Es de Microsoft y viene con Windows Pro/Enterprise.</p><p>Después hay que <b>reiniciar</b> para poder usarla.</p>`,
    [{t:'Cancelar'}, {t:'Activar', c:'pri', f: async () => { toast('Activando Windows Sandbox…'); const m = await caSbEnable(); toast(esc(m || 'Activado.')); SB.status = await caSbStatus(); sbDraw(); }}]);
}
function sbResultHTML(R){
  const v = SBV[R.verdict] || SBV['No concluyente'];
  const FLAGP = {sospechoso:'<span class="st st-a">Sospechoso</span>', peligroso:'<span class="st st-r">Peligroso</span>', esperado:'<span class="st st-n">Esperado</span>'};
  const procs = (R.procs || []).map(x => `<div class="sb-pr ${x.flag}"><div class="n" style="padding-left:${x.depth * 18}px">${x.depth ? '<i class="pr-br"></i>' : ''}<b>${esc(x.name)}</b><span class="t">+${(x.t||0).toFixed(1)} s</span>${FLAGP[x.flag] || ''}</div>${x.cmd ? `<code>${esc(x.cmd)}</code>` : ''}${x.why ? `<small>${esc(x.why)}</small>` : ''}</div>`).join('');
  return `<div class="sb-card done">${sbHead('Resultado de abrir el archivo en Windows Sandbox (sin red)')}
    <div class="fa-verdict ${v[0]} sb-v"><span class="fa-vi"><i class="ic">${ic(v[1])}</i></span><div class="fa-vt"><small>En el entorno aislado</small><b>${esc(R.verdict)}</b><span>${esc(R.summary || '')}</span></div></div>
    ${sbViewer()}
    <div class="sb-grid">
      <div><h4>Procesos que se lanzaron${R.viewer ? ` · se abrió con ${esc(R.viewer)}` : ''}</h4>${procs || '<div class="fa-empty">No se lanzó ningún proceso.</div>'}</div>
      <div><h4>Qué se ha encontrado</h4>${(R.findings || []).map(f => { const l = FAL[f.level] || FAL.info; return `<div class="fa-f ${l[0]}"><i class="ic">${ic(l[1])}</i><div><b>${esc(f.title)}</b><span>${esc(f.detail)}</span></div></div>`; }).join('') || '<div class="fa-empty">Nada.</div>'}
        <h4 style="margin-top:16px">Inicio automático</h4>${(R.persist || []).length ? R.persist.map(x => `<code class="sb-line">${esc(x)}</code>`).join('') : '<div class="fa-empty">No ha dejado nada que arranque con Windows.</div>'}
        <h4 style="margin-top:16px">Documentos señuelo</h4><div class="fa-empty">${esc(R.decoys || '—')}</div>
        <h4 style="margin-top:16px">Archivos creados o cambiados (${(R.files || []).length})</h4>${(R.files || []).slice(0, 30).map(f => `<code class="sb-line ${f.flag ? 'bad' : ''}">${esc(f.p)} · ${fBytes(f.s)}</code>`).join('') || '<div class="fa-empty">Ninguno fuera de lo normal.</div>'}</div>
    </div>
    <div class="sb-go"><span class="sp"></span><button class="btn sm" onclick="SB.id=null;SB.poll=null;sbDraw()">Volver a probar</button></div></div>`;
}""")
rep("""          ${kv('Huella SHA-256', `<code>${esc(r.sha256)}</code>`""", """          ${kv('Huella SHA-256', `<code>${esc(r.sha256)}</code>`""")
# llamar a sbInit al pintar el resultado
t = doc.t
i = t.index('function faRender(){')
j = t.index('function faIsolate(){', i)
body = t[i:j]
k = body.rindex('`;\n}')
body = body[:k] + '`;\n  sbInit();\n}' + body[k+4:]
doc.t = t[:i] + body + t[j:]
# texto de la tarjeta de elegir archivo
rep("Lo revisa <b>el motor propio de BlueShieldAA, por dentro y sin abrirlo ni ejecutarlo</b>:",
    "Primero lo revisa <b>el motor propio de BlueShieldAA, por dentro y sin abrirlo</b>; después, si quieres, lo puedes <b>abrir en un entorno aislado</b> (Windows Sandbox) y ver lo que hace de verdad:")
