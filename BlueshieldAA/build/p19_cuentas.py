# 4.2: Protección → Mis cuentas: cuentas de Google, Microsoft, etc. que hay en el equipo, con
# acceso directo a sus páginas oficiales de actividad, dispositivos y ubicación, y los inicios de
# sesión en ESTE equipo (registro de seguridad de Windows).

rep("['leaks','Filtraciones']", "['leaks','Filtraciones'],['accounts','Mis cuentas']")
rep("leaks:'Contraseñas y correos filtrados'", "leaks:'Contraseñas y correos filtrados', accounts:'Mis cuentas'")
rep("leaks:'Comprueba si", "accounts:'Tus cuentas de Google, Microsoft y otras que hay en este equipo, y dónde y desde qué dispositivos se ha entrado en ellas.', leaks:'Comprueba si")
rep('  <div class="page fill" id="p-clean">', r'''  <div class="page fill" id="p-accounts">
    <div class="phead"><div class="grow"><h1>Mis cuentas</h1><div class="sub">${SUBS.accounts}</div></div><div id="acSubtabs"></div>
      <button class="btn sm" onclick="acLoad(true)"><i class="ic">${ic('refresh')}</i>Volver a buscar</button></div>
    <div class="hw-scroll">
      <div class="card ac-note"><i class="ic">${ic('info')}</i><div><b>Cómo ver dónde se ha entrado en tus cuentas</b><span>Google y Microsoft no dejan que un programa lea el historial de inicios de sesión de una cuenta personal sin registrarse con claves, y BlueShieldAA no te pide contraseñas. Por eso cada botón abre la <b>página oficial</b> de esa cuenta en tu navegador (donde ya tienes la sesión iniciada): ahí ves cada inicio de sesión con fecha, ciudad, país, IP y dispositivo, y puedes cerrar los que no reconozcas.</span></div></div>
      <div id="acList"></div>
      <div class="card ac-add"><b>¿Falta alguna?</b><span>Añade un correo para tener a mano sus enlaces y comprobar filtraciones (se guarda solo en este equipo).</span><div class="listin"><input id="acNew" placeholder="tucorreo@ejemplo.com" onkeydown="if(event.key==='Enter')acAdd()"><button class="btn pri" onclick="acAdd()">Añadir</button></div></div>
      <div class="card ac-log"><div class="dv-gh"><span class="hw-ci" style="--c:var(--vio)"><i class="ic">${ic('pc')}</i></span><b>Inicios de sesión en este equipo</b><span class="sp"></span><button class="btn sm" id="acLogBtn" onclick="acLogons()">Ver los últimos 14 días</button></div><div id="acLog" class="ac-logb"><p class="help" style="margin:0">Quién ha entrado en Windows en este PC: en persona, al desbloquear o por Escritorio remoto, y desde qué IP y país. Se lee del registro de seguridad de Windows (no sale nada del equipo).</p></div></div>
    </div>
  </div>

  <div class="page fill" id="p-clean">''')
rep("  if (p === 'clean') clInit(); else clStop();", "  if (p === 'clean') clInit(); else clStop();\n  if (p === 'accounts') acInit();")
rep("/* ====================== Procesos ====================== */", r"""/* ====================== Mis cuentas ====================== */
const AC = {d:null, extra:(() => { try { return JSON.parse(localStorage.getItem('bsAccounts') || '[]'); } catch (e) { return []; } })()};
const ACP = {'Google':['#ea4335','G'], 'Microsoft':['#0078d4','M'], 'Microsoft (trabajo o centro educativo)':['#5b5fc7','M'], 'Apple':['#555','A'], 'Yahoo':['#6001d2','Y'], 'Proton':['#6d4aff','P'], 'Otro':['#64748b','@']};
const AC_LINKS = {'gmail.com':'Google','googlemail.com':'Google','outlook.com':'Microsoft','outlook.es':'Microsoft','hotmail.com':'Microsoft','hotmail.es':'Microsoft','live.com':'Microsoft','msn.com':'Microsoft','icloud.com':'Apple','me.com':'Apple','yahoo.com':'Yahoo','yahoo.es':'Yahoo','proton.me':'Proton','protonmail.com':'Proton'};
function acInit(){ $('#acSubtabs').innerHTML = subtabsHTML('accounts'); if (!AC.d) acLoad(); else acRender(); }
async function acLoad(manual){ try { AC.d = await caAccounts(); } catch (e) { AC.d = {accounts:[]}; } acRender(); if (manual) toast('Cuentas buscadas de nuevo.'); }
function acAdd(){
  const i = $('#acNew'), v = i.value.trim().toLowerCase(); if (!/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/.test(v)) { toast('Escribe un correo válido.'); return; }
  if (!AC.extra.includes(v)) AC.extra.push(v); try { localStorage.setItem('bsAccounts', JSON.stringify(AC.extra)); } catch (e) {} i.value = ''; acRender();
}
function acRemove(v){ AC.extra = AC.extra.filter(x => x !== v); try { localStorage.setItem('bsAccounts', JSON.stringify(AC.extra)); } catch (e) {} acRender(); }
function acLeak(mail){ showPage('leaks'); setTimeout(() => { const i = $('#lkMail'); if (i) { i.value = mail; lkCheckMail(); } }, 250); }
function acRender(){
  const box = $('#acList'); if (!box) return;
  if (!AC.d) { box.innerHTML = '<div class="card hw-wait"><span class="cl-spin"></span><b>Buscando cuentas en el equipo…</b></div>'; return; }
  const l = [...(AC.d.accounts || [])];
  const known = new Set(l.map(a => a.email));
  // las añadidas a mano: mismos enlaces según el dominio
  const tpl = {}; l.forEach(a => { if (!tpl[a.provider]) tpl[a.provider] = a.links; });
  AC.extra.filter(e => !known.has(e)).forEach(e => { const p = AC_LINKS[e.split('@')[1]] || 'Otro'; l.push({email:e, provider:p, sources:['Añadida a mano'], links: tpl[p] || acDefLinks(p), manual:true}); });
  if (!l.length) { box.innerHTML = `<div class="card hw-wait"><b>No se ha encontrado ninguna cuenta</b><span>Se buscan en Windows, Office/Outlook, Chrome, Edge, Brave, Firefox y Thunderbird del usuario ${esc(AC.d.user || '')}. Puedes añadir tus correos abajo.</span></div>`; return; }
  box.innerHTML = `<div class="ac-grid">${l.map(a => { const p = ACP[a.provider] || ACP['Otro'];
    return `<div class="card ac-c"><div class="ac-h"><span class="ac-av" style="background:${p[0]}">${p[1]}</span><div><b>${esc(a.email)}</b><small>${esc(a.name ? a.name + ' · ' : '')}${esc(a.provider === 'Otro' ? 'Otro proveedor' : 'Cuenta de ' + a.provider)}</small></div>
        ${a.manual ? `<button class="btn sm ghost" title="Quitar" onclick="acRemove('${esc(a.email)}')">×</button>` : ''}</div>
      <div class="ac-src">${(a.sources || []).map(s => `<span>${esc(s)}</span>`).join('')}</div>
      <div class="ac-links">${(a.links || []).length ? a.links.map((k, i) => `<button class="ac-l ${i === 0 ? 'pri' : ''}" onclick="caOpenURL('${esc(k.url)}')"><b><i class="ic">${ic(i === 0 ? 'pc' : i === 1 ? 'pulse' : 'shield')}</i>${esc(k.t)}<i class="ic ext">${ic('ext')}</i></b><small>${esc(k.d)}</small></button>`).join('')
        : '<p class="help" style="margin:0">Este proveedor no tiene una página pública de actividad conocida. Entra en la configuración de seguridad de tu cuenta.</p>'}</div>
      <div class="ac-f"><button class="btn sm" onclick="acLeak('${esc(a.email)}')"><i class="ic">${ic('search')}</i>¿Está en alguna filtración?</button></div></div>`; }).join('')}</div>`;
}
function acDefLinks(p){
  return {Google:[{t:'Dispositivos con la sesión iniciada', url:'https://myaccount.google.com/device-activity', d:'Ordenadores y móviles con la cuenta abierta, con ciudad y última actividad.'}],
    Microsoft:[{t:'Actividad reciente (inicios de sesión)', url:'https://account.live.com/Activity', d:'Cada inicio de sesión con fecha, país, IP y navegador.'}],
    Apple:[{t:'Cuenta de Apple: dispositivos', url:'https://account.apple.com/account/manage/section/devices', d:'iPhone, iPad y Mac con tu cuenta.'}],
    Yahoo:[{t:'Actividad reciente', url:'https://login.yahoo.com/account/activity', d:'Inicios de sesión y aplicaciones conectadas.'}]}[p] || [];
}
async function acLogons(){
  const b = $('#acLogBtn'); b.disabled = true; b.textContent = 'Leyendo…';
  $('#acLog').innerHTML = '<div class="hw-wait" style="padding:20px"><span class="cl-spin"></span><b>Leyendo el registro de seguridad de Windows…</b></div>';
  let r; try { r = await caLogons(); } catch (e) { r = {error:'No se ha podido leer.'}; }
  b.disabled = false; b.textContent = 'Volver a leer';
  if (r.error) { $('#acLog').innerHTML = `<div class="rw-err"><i class="ic">${ic('alert')}</i>${esc(r.error)}</div>`; return; }
  const l = r.logons || [];
  const kc = {'En el equipo':'g', 'Desbloqueo':'n', 'Escritorio remoto':'a', 'Sin conexión (credenciales guardadas)':'n'};
  $('#acLog').innerHTML = `${r.failed ? `<div class="ac-fail"><i class="ic">${ic('alert')}</i><div><b>${r.failed} intento(s) fallido(s) de iniciar sesión en 14 días</b>${(r.failedIPs || []).length ? `<span>Desde: ${r.failedIPs.map(f => `<span class="mono">${esc(f.ip)}</span>${f.cc ? ` <span class="cc">${esc(f.cc)}</span>` : ''}${f.org ? ' ' + esc(f.org) : ''} (${f.n})`).join(' · ')}</span>` : '<span>Contraseñas mal escritas en este equipo.</span>'}</div></div>` : ''}
    ${l.length ? `<div class="ac-t"><div class="ac-th"><div>Cuándo</div><div>Usuario</div><div>Cómo</div><div>Desde</div></div>${l.map(x => `<div class="ac-tr ${x.pub ? 'pub' : ''}"><div>${new Date(x.t).toLocaleString('es-ES', {day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit'})}</div><div>${esc(x.u)}</div>
      <div><span class="tsv t-${kc[x.kind] || 'n'}">${esc(x.kind || x.ty)}</span></div><div>${x.ip ? `<span class="mono">${esc(x.ip)}</span>${x.cc ? ` <span class="cc">${esc(x.cc)}</span>` : ''}${x.org ? ' · ' + esc(x.org) : ''}${x.pub ? ' · <b style="color:var(--amber-ink)">desde Internet</b>' : ''}` : (x.ws ? esc(x.ws) : 'este equipo')}</div></div>`).join('')}</div>`
      : '<p class="help">No hay inicios de sesión en los últimos 14 días (o el registro se ha vaciado).</p>'}`;
}

/* ====================== Procesos ====================== */""")
