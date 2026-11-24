# 4.2: Mantenimiento → Hardware dividido en Componentes (lo de dentro del equipo con su
# salud) y Dispositivos conectados (ratones, teclados, cascos, pantallas, USB, Bluetooth…).

rep("hw:'Salud del hardware'", "hw:'Hardware'")
rep("hw:'Discos, batería, espacio libre, antigüedad del equipo y garantía.'",
    "hw:'Lo que lleva dentro tu equipo y todo lo que tiene conectado (ratón, teclado, cascos, pantallas, USB, Bluetooth), con su estado.'")
rep('  <div class="page fill" id="p-clean">', r'''  <div class="page fill" id="p-hw">
    <div class="phead"><div class="grow"><h1>Hardware</h1><div class="sub">${SUBS.hw}</div></div><div id="hwSubtabs"></div>
      <div class="seg" id="hwTab"></div>
      <button class="btn sm" onclick="caDevManager()"><i class="ic">${ic('ext')}</i>Administrador de dispositivos</button></div>
    <div class="hw-scroll" id="hwBody"></div>
  </div>

  <div class="page fill" id="p-clean">''')
rep("  if (p === 'clean') clInit(); else clStop();", "  if (p === 'clean') clInit(); else clStop();\n  if (p === 'hw') hwInit(); else hwStop();")
rep("/* ====================== Procesos ====================== */", r"""/* ====================== Hardware ====================== */
const HW = {tab:'comp', info:null, dev:null, timer:0, open:null, onlyBad:false};
const DCAT = {'Ratones y punteros':'target', 'Teclados':'grid', 'Auriculares y cascos':'bell', 'Audio':'bell', 'Micrófonos':'bell', 'Pantallas':'pc', 'Mandos de juego':'target', 'Cámaras y escáneres':'search',
  'Impresoras':'file', 'Almacenamiento y teléfonos':'usb', 'Seguridad':'lock', 'Red':'net', 'Bluetooth':'net', 'Otros':'box', 'Tarjetas gráficas':'pc', 'Sistema':'cpu', 'Procesador':'cpu',
  'Controladoras de almacenamiento':'disk', 'Almacenamiento':'disk', 'USB':'usb', 'Dispositivos de entrada':'grid', 'Sensores':'pulse', 'Batería':'bolt', 'Software':'code', 'Firmware':'cpu', 'Puertos':'usb'};
function hwInit(){ $('#hwSubtabs').innerHTML = subtabsHTML('hw'); hwTabs(); hwRender(); hwLoad(); clearInterval(HW.timer); HW.timer = setInterval(() => { if (S.page === 'hw' && !document.hidden && HW.tab !== 'comp') hwLoadDev(); }, 5000); }
function hwStop(){ clearInterval(HW.timer); HW.timer = 0; }
async function hwLoad(){ try { HW.info = await caHardware(); } catch (e) {} if (HW.tab === 'comp') hwRender(); hwLoadDev(); if (HW.info && HW.info.ready === false) setTimeout(() => { if (S.page === 'hw') hwLoad(); }, 4000); }
async function hwLoadDev(){ try { HW.dev = await caDevices(); } catch (e) {} hwTabs(); if (HW.tab !== 'comp') hwRender(); }
function hwTabs(){
  const ext = (HW.dev || {}).external || [], bad = ((HW.dev || {}).internal || []).filter(d => d.status === 'problema').length;
  $('#hwTab').innerHTML = [['comp','Componentes'],['ext','Conectados' + (HW.dev ? ` · ${ext.length}` : '')],['int','Todos los dispositivos' + (bad ? ` · ${bad} con problemas` : '')]]
    .map(([k, n]) => `<button class="${HW.tab === k ? 'on' : ''}" onclick="HW.tab='${k}';hwTabs();hwRender()">${n}</button>`).join('');
}
function hwRender(){ const b = $('#hwBody'); if (!b) return; b.innerHTML = HW.tab === 'comp' ? hwCompHTML() : hwDevHTML(HW.tab === 'ext'); }
const hwKV = (k, v) => v || v === 0 ? `<div class="hw-kv"><span>${k}</span><b>${v}</b></div>` : '';
function hwHealth(match){
  const it = S.items.filter(i => i.category === 'Hardware' && match(i));
  return it.map(i => `<div class="hw-hl ${PENDING.includes(i.status) ? 'bad' : 'ok'}" onclick="goItem('${esc(i.id)}')"><i class="ic">${ic(PENDING.includes(i.status) ? 'alert' : 'check')}</i><span><b>${esc(i.name)}</b> · ${esc(i.current || '')}</span>${pill(i.status)}</div>`).join('');
}
function hwCompHTML(){
  const h = HW.info;
  if (!h || h.ready === false) return '<div class="card hw-wait"><span class="cl-spin"></span><b>Leyendo los componentes del equipo…</b><span>La primera vez tarda unos segundos; después sale al momento.</span></div>';
  const card = (icon, color, title, sub, body, health) => `<div class="card hw-c" style="--c:${color}"><div class="hw-ch"><span class="hw-ci"><i class="ic">${ic(icon)}</i></span><div><b>${title}</b><small>${sub || ''}</small></div></div>${body}${health || ''}</div>`;
  const mods = h.modules || [], gpus = h.gpus || [], disks = h.disks || [], nics = h.nics || [];
  const memUsed = mods.length, slots = h.slots || 0;
  const bad = S.items.filter(i => i.category === 'Hardware' && PENDING.includes(i.status));
  return `<div class="card hw-pc"><span class="hw-pci"><i class="ic">${ic('pc')}</i></span><div class="hw-pct"><b>${esc([h.sysMaker, h.sysModel].filter(Boolean).join(' ') || h.board || h.computer || 'Este equipo')}</b>
      <span>${esc(h.computer || '')} · ${esc(h.osName || h.os || 'Windows')}${h.osVersion ? ' ' + esc(h.osVersion) : ''}${h.osBuild ? ` <span class="mono">(${esc(h.osBuild)})</span>` : ''}</span></div>
      <div class="hw-pcs">${bad.length ? `<span class="st st-a">${stIcon('Revisar')}<span>${bad.length} aviso(s) de salud</span></span>` : `<span class="st st-g">${stIcon('Al día')}<span>Todo en buen estado</span></span>`}</div></div>
    <div class="hw-grid">
    ${card('cpu', '#3b82f6', 'Procesador', esc(h.cpu || '—'), hwKV('Núcleos', h.cores ? `${h.cores} núcleos · ${h.threads || h.logical} hilos` : (h.logical ? h.logical + ' hilos' : '')) + hwKV('Velocidad base', h.baseMHz ? (h.baseMHz / 1000).toFixed(2) + ' GHz' : '') + hwKV('Caché', h.l3 ? `L2 ${fBytes((h.l2 || 0) * 1024)} · L3 ${fBytes(h.l3 * 1024)}` : '') + hwKV('Virtualización', h.virt === undefined ? '' : h.virt ? 'activada' : 'desactivada en la BIOS'))}
    ${card('grid', '#8b5cf6', 'Memoria RAM', `${fBytes(h.memTotal || 0)}${h.memType ? ' · ' + esc(h.memType) : ''}${h.memSpeed ? ' · ' + h.memSpeed + ' MT/s' : ''}`, hwKV('Ranuras', slots ? `${memUsed} de ${slots} ocupadas${slots > memUsed ? ' · se puede ampliar' : ''}` : (memUsed ? memUsed + ' módulos' : '')) + mods.map(m => hwKV(esc(m.bank || 'Módulo'), `${fBytes(m.size)}${m.speed ? ' · ' + m.speed + ' MT/s' : ''}${m.maker && !/^0+$|unknown/i.test(m.maker) ? ' · ' + esc(m.maker) : ''}`)).join(''))}
    ${card('pc', '#06b6d4', 'Tarjeta gráfica', gpus.length ? esc(gpus[0].name) : '—', gpus.map(g => hwKV(esc(g.name), g.driver ? 'controlador ' + esc(g.driver) : '')).join(''))}
    ${card('disk', '#f97316', 'Almacenamiento', disks.length ? disks.length + ' disco' + (disks.length > 1 ? 's' : '') + ' · ' + fBytes(disks.reduce((a, d) => a + (d.size || 0), 0)) : '—', disks.map(d => hwKV(esc(d.name), `${esc([d.media, d.bus].filter(x => x && x !== 'Unspecified').join(' · '))} · ${fBytes(d.size)}${d.health ? ` · <span class="${/healthy/i.test(d.health) ? 'ok' : 'bad'}">${/healthy/i.test(d.health) ? 'en buen estado' : esc(d.health)}</span>` : ''}`)).join(''), hwHealth(i => i.id.startsWith('hw:disk') || i.id === 'hw:sysfree'))}
    ${card('bolt', '#22c55e', 'Batería', S.items.some(i => i.id === 'hw:bat') ? '' : 'Sin batería o no se ha podido leer', '', hwHealth(i => i.id === 'hw:bat'))}
    ${card('box', '#64748b', 'Placa base y BIOS', esc([h.boardMaker, h.boardModel].filter(Boolean).join(' ') || h.board || '—'), hwKV('BIOS', esc([h.biosVendor, h.bios].filter(Boolean).join(' '))) + hwKV('Fecha de la BIOS', esc(h.biosDate || '')))}
    ${card('net', '#14b8a6', 'Red', nics.length ? nics.length + ' conectada' + (nics.length > 1 ? 's' : '') : 'sin conexión activa', nics.map(n => hwKV(esc(n.name), `${esc(n.desc || '')}${n.speed ? ' · ' + esc(n.speed) : ''}`)).join(''))}
    ${card('win', '#0ea5e9', 'Windows', esc(h.osName || h.os || 'Windows'), hwKV('Versión', esc(h.osVersion || '')) + hwKV('Compilación', h.osBuild ? `<span class="mono">${esc(h.osBuild)}</span>` : '') + hwKV('Encendido desde', h.boot ? new Date(h.boot).toLocaleString('es-ES') : ''))}
    </div>`;
}
function hwDevHTML(ext){
  const d = HW.dev; if (!d) return '<div class="card hw-wait"><span class="cl-spin"></span><b>Buscando dispositivos…</b></div>';
  let l = ext ? d.external : d.internal;
  const usb = d.external.filter(x => x.conn === 'USB').length, bt = d.external.filter(x => x.conn === 'Bluetooth').length;
  const bad = l.filter(x => x.status !== 'ok').length;
  if (HW.onlyBad) l = l.filter(x => x.status !== 'ok');
  const tile = (c, i, k, v, h) => `<div class="pst" style="--c:${c};cursor:default"><span class="pst-ic"><i class="ic">${ic(i)}</i></span><span class="pst-t"><small>${k}</small><b>${v}</b><em>${h}</em></span></div>`;
  const tiles = ext ? tile('var(--accent)', 'usb', 'Conectados', d.external.length, 'aparatos fuera del equipo') + tile('var(--vio)', 'usb', 'Por USB', usb, 'cable o receptor') + tile('#0ea5e9', 'net', 'Por Bluetooth', bt, 'emparejados y presentes') + tile(bad ? 'var(--red)' : 'var(--green)', bad ? 'alert' : 'check', 'Con problemas', bad, bad ? 'mira abajo qué les pasa' : 'todos funcionan')
    : tile('var(--accent)', 'cpu', 'Dispositivos', d.internal.length, 'dentro del equipo') + tile(bad ? 'var(--red)' : 'var(--green)', bad ? 'alert' : 'check', 'Con problemas', bad, bad ? 'controlador o fallo' : 'todos funcionan');
  const cats = {}; l.forEach(x => (cats[x.cat] = cats[x.cat] || []).push(x));
  const order = Object.keys(cats).sort((a, b) => (cats[b].some(x => x.status !== 'ok') - cats[a].some(x => x.status !== 'ok')) || a.localeCompare(b));
  const conn = c => c === 'Bluetooth' ? `<span class="dv-cn bt"><i class="ic">${ic('net')}</i>Bluetooth</span>` : c === 'USB' ? `<span class="dv-cn usb"><i class="ic">${ic('usb')}</i>USB</span>` : `<span class="dv-cn">${esc(c)}</span>`;
  const st = x => x.status === 'ok' ? `<span class="st st-g">${stIcon('Al día')}<span>Funciona</span></span>` : x.status === 'desactivado' ? `<span class="st st-n">${stIcon('Info')}<span>Desactivado</span></span>` : `<span class="st st-r">${stIcon('Falló')}<span>Problema</span></span>`;
  return `<div class="ap-sum ${ext ? '' : 'two'}">${tiles}</div>
    ${!ext || bad ? `<div class="ap-bar"><div class="chips"><button class="chip ${!HW.onlyBad ? 'on' : ''}" onclick="HW.onlyBad=false;hwRender()">Todos</button><button class="chip ${HW.onlyBad ? 'on' : ''}" onclick="HW.onlyBad=true;hwRender()">Solo con problemas<span class="n">${bad}</span></button></div></div>` : ''}
    ${order.length ? order.map(c => `<div class="card dv-g"><div class="dv-gh"><span class="hw-ci" style="--c:var(--accent)"><i class="ic">${ic(DCAT[c] || 'box')}</i></span><b>${esc(c)}</b><span class="n">${cats[c].length}</span></div>
      ${cats[c].map(x => { const open = HW.open === x.id; const id = esc(x.id).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
        return `<div class="dv-r ${x.status !== 'ok' ? 'bad' : ''} ${open ? 'open' : ''}" onclick="HW.open=HW.open==='${id}'?null:'${id}';hwRender()">
          <div class="dv-n"><b>${esc(x.name)}</b><small>${esc([x.mfg, (x.funcs || []).join(' · ')].filter(Boolean).join(' — '))}</small></div>
          <div>${conn(x.conn)}</div>
          <div class="mono dv-v">${x.drvVer ? `<span title="Versión del controlador">${esc(x.drvVer)}</span>` : '<span class="ap-na">—</span>'}${x.fwVer ? `<small title="Firmware">firmware ${esc(x.fwVer)}</small>` : ''}</div>
          <div>${st(x)}</div></div>
          ${x.problem ? `<div class="dv-p"><i class="ic">${ic('alert')}</i>${esc(x.problem)}</div>` : ''}
          ${open ? `<div class="dv-det">${x.vidPid ? hwKV('Fabricante:producto (VID:PID)', `<span class="mono">${esc(x.vidPid)}</span>`) : ''}${hwKV('Controlador', esc(x.drvVer || '—'))}${x.fwVer ? hwKV('Firmware', esc(x.fwVer)) : ''}
            <div class="dv-parts"><small>Funciones que ve Windows</small>${(x.parts || []).map(p => `<div><span>${esc(p.name || p.class)}</span><code>${esc(p.instance)}</code></div>`).join('')}</div></div>` : ''}`; }).join('')}</div>`).join('')
      : `<div class="card hw-wait"><b>${HW.onlyBad ? 'Ningún dispositivo con problemas.' : ext ? 'No hay nada conectado al equipo ahora mismo.' : 'No se han encontrado dispositivos.'}</b>${ext ? '<span>Conecta un ratón, unos cascos o un USB y aparecerá aquí en unos segundos.</span>' : ''}</div>`}`;
}

/* ====================== Procesos ====================== */""")
