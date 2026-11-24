# Ventana de progreso 4.0: una escena con sentido para cada tarea (analizar, actualizar,
# Windows Update, limpiar, ajustes de seguridad, punto de restauración, terminado), con datos
# reales (porcentaje de descarga, comprobaciones hechas, cola de elementos) y consola de
# órdenes en directo. Misma estética isométrica; sin bloques flotando.
t = doc.t
a = t.index('<svg class="isoscene" viewBox="0 40 300 215" aria-hidden="true">')
b = t.index('<div class="isohud">', a)
old = t[a:b]
plat_start = old.index('<polygon class="plat-top"')
pc_start = old.index('<polygon class="tower-top"')
mon_start = old.index('<polygon class="base-top"')
screen_start = old.index('<polygon class="iso-screen"')
clip_start = old.index('<g clip-path="url(#scrClip)">')
cube_start = old.index('<g class="cube c0">')
platform = old[plat_start:pc_start]
tower = old[pc_start:mon_start]
monitor = old[mon_start:screen_start]
screen = old[screen_start:clip_start]
codebars = old[clip_start:cube_start]  # <g clip-path=…> … </g> (líneas de código + escaneo)

SCR = 'matrix(0.403 0.227 0 0.351 104.9 99.5)'   # pantalla → cuadro local 100×100
FLR = 'matrix(1.242 0.702 -1.242 0.702 150 107)'  # suelo de la plataforma → 100×100

new = f'''<svg class="isoscene" id="isoScene" viewBox="0 14 300 246" aria-hidden="true">
        <defs>
          <radialGradient id="scrG" cx="35%" cy="35%" r="80%"><stop offset="0" stop-color="#0a3a52"/><stop offset=".55" stop-color="#06202f"/><stop offset="1" stop-color="#030e16"/></radialGradient>
          <clipPath id="scrClip"><polygon points="104.9,134.6 145.2,157.3 145.2,122.2 104.9,99.5"/></clipPath>
          <linearGradient id="sweepG" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="var(--mc)" stop-opacity="0"/><stop offset="1" stop-color="var(--mc)" stop-opacity=".55"/></linearGradient>
          <linearGradient id="beamG" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--mc)" stop-opacity=".05"/><stop offset=".5" stop-color="var(--mc)" stop-opacity=".55"/><stop offset="1" stop-color="var(--mc)" stop-opacity=".1"/></linearGradient>
          <linearGradient id="shieldG" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--mc)" stop-opacity=".30"/><stop offset="1" stop-color="var(--mc)" stop-opacity=".04"/></linearGradient>
          <linearGradient id="binG" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#1b2a49"/><stop offset=".55" stop-color="#223150"/><stop offset="1" stop-color="#0f1626"/></linearGradient>
          <filter id="glw" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="2.2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
          <g id="pcMon">{monitor}<polygon class="ghost-scr" points="104.9,134.6 145.2,157.3 145.2,122.2 104.9,99.5"/></g>
        </defs>
        <ellipse class="iso-floorglow" cx="150" cy="212" rx="120" ry="30"/>
        {platform}
        <!-- suelo: radar y puntos de comprobación -->
        <g transform="{FLR}">
          <g class="m-scan">
            <circle class="rad-ring" cx="50" cy="50" r="22"/><circle class="rad-ring" cx="50" cy="50" r="34"/><circle class="rad-ring" cx="50" cy="50" r="46"/>
            <g><path class="rad-sweep" d="M50 50 L96 50 A46 46 0 0 0 82.5 17.5 Z"/><animateTransform attributeName="transform" type="rotate" from="0 50 50" to="360 50 50" dur="3.2s" repeatCount="indefinite"/></g>
          </g>
          <g class="m-fix m-restore m-done"><circle class="pulse-ring" cx="50" cy="50" r="30"/><circle class="pulse-ring p2" cx="50" cy="50" r="30"/></g>
          <g id="flDots"></g>
        </g>
        <!-- escudo detrás del equipo (ajustes de seguridad) -->
        <g class="m-fix">
          <path class="shield" d="M150 40 L188 55 V86 C188 113 170 130 150 138 C130 130 112 113 112 86 V55 Z"/>
          <path class="shield-chk" d="M135 86 L146 97 L167 74"/>
        </g>
        <!-- copias del monitor (punto de restauración) -->
        <g class="m-restore"><g class="ghost g2"><use href="#pcMon" transform="translate(-22,-13)"/></g><g class="ghost g1"><use href="#pcMon" transform="translate(-11,-6.5)"/></g></g>
        {tower}
        <!-- descarga: nube → torre -->
        <g class="m-update m-winupdate">
          <path class="beam" d="M207 66 L215 66 L212 112 L208 112 Z"/>
          <line class="beam-dash" x1="211" y1="66" x2="210" y2="112"/>
          <g class="pkt"><path d="M0 -3 L5 0 L0 3 L-5 0 Z"/><animateMotion dur="1.3s" repeatCount="indefinite" path="M211 66 L210 113"/><animate attributeName="opacity" values="0;1;1;0" dur="1.3s" repeatCount="indefinite"/></g>
          <g class="pkt"><path d="M0 -3 L5 0 L0 3 L-5 0 Z"/><animateMotion dur="1.3s" begin=".43s" repeatCount="indefinite" path="M211 66 L210 113"/><animate attributeName="opacity" values="0;1;1;0" dur="1.3s" begin=".43s" repeatCount="indefinite"/></g>
          <g class="pkt"><path d="M0 -3 L5 0 L0 3 L-5 0 Z"/><animateMotion dur="1.3s" begin=".86s" repeatCount="indefinite" path="M211 66 L210 113"/><animate attributeName="opacity" values="0;1;1;0" dur="1.3s" begin=".86s" repeatCount="indefinite"/></g>
          <g class="cloud" filter="url(#glw)">
            <path d="M197 62 a8 8 0 0 1 2-15.6 a11 11 0 0 1 21-3.4 a8.5 8.5 0 0 1 13 7.4 a6 6 0 0 1-1 11.6 Z"/>
          </g>
          <g class="m-update cl-arrow"><path d="M214 45 V57 M209.5 52.5 L214 57 L218.5 52.5"/></g>
          <g class="m-winupdate cl-win"><rect x="208.5" y="45" width="5.2" height="5.2"/><rect x="214.6" y="45" width="5.2" height="5.2"/><rect x="208.5" y="51.1" width="5.2" height="5.2"/><rect x="214.6" y="51.1" width="5.2" height="5.2"/></g>
          <ellipse class="land" cx="209.8" cy="118" rx="12" ry="6.8"/>
        </g>
        {monitor}
        {screen}
        {codebars.replace('<g clip-path="url(#scrClip)">', '<g clip-path="url(#scrClip)" class="m-scan">')}
        <!-- contenido de la pantalla (cuadro local 100×100) -->
        <g clip-path="url(#scrClip)"><g transform="{SCR}">
          <g class="scr-chrome"><rect x="6" y="6" width="88" height="9" rx="2"/><circle cx="11" cy="10.5" r="1.6"/><circle cx="16" cy="10.5" r="1.6"/><circle cx="21" cy="10.5" r="1.6"/></g>
          <g class="m-scan lens"><circle cx="0" cy="0" r="10"/><path d="M7 7 L15 15"/><animateMotion dur="3.6s" repeatCount="indefinite" path="M30 35 C55 25 75 40 70 60 C65 80 35 80 30 60 C26 45 28 38 30 35"/></g>
          <g class="m-update s-arrow"><path d="M50 22 V50 M39 39 L50 50 L61 39"/><path d="M36 56 H64"/></g>
          <g class="m-winupdate s-win"><rect x="36" y="24" width="13" height="13"/><rect x="51" y="24" width="13" height="13"/><rect x="36" y="39" width="13" height="13"/><rect x="51" y="39" width="13" height="13"/></g>
          <g class="m-clean s-broom"><path d="M50 20 L50 46"/><path d="M40 46 H60 L64 60 H36 Z"/><path d="M41 60 V52 M47 60 V52 M53 60 V52 M59 60 V52"/></g>
          <g class="m-fix s-tog">
            <rect class="tl" x="12" y="25" width="40" height="5" rx="2.5"/><rect class="tt t1" x="62" y="22" width="26" height="12" rx="6"/><circle class="tk k1" cx="68" cy="28" r="4.2"/>
            <rect class="tl" x="12" y="44" width="34" height="5" rx="2.5"/><rect class="tt t2" x="62" y="41" width="26" height="12" rx="6"/><circle class="tk k2" cx="68" cy="47" r="4.2"/>
            <rect class="tl" x="12" y="63" width="44" height="5" rx="2.5"/><rect class="tt t3" x="62" y="60" width="26" height="12" rx="6"/><circle class="tk k3" cx="68" cy="66" r="4.2"/>
          </g>
          <g class="m-restore s-clock"><circle cx="50" cy="44" r="20"/><path class="hand" d="M50 44 V30"><animateTransform attributeName="transform" type="rotate" from="0 50 44" to="-360 50 44" dur="2.4s" repeatCount="indefinite"/></path><path d="M50 44 L60 50"/><path d="M27 32 L30 38 L36 36"/></g>
          <g class="m-update m-winupdate m-clean bar"><rect class="trk" x="12" y="70" width="76" height="9" rx="4.5"/><rect class="fill" id="scrFill" x="12" y="70" width="0" height="9" rx="4.5"/><rect class="ind" x="12" y="70" width="22" height="9" rx="4.5"/></g>
          <g class="m-done s-ok"><circle cx="50" cy="48" r="26"/><path d="M37 49 L47 59 L65 38"/></g>
          <rect class="flash" x="0" y="0" width="100" height="100"/>
        </g></g>
        <!-- papelera y hojas (limpieza) -->
        <g class="m-clean">
          <g class="sheet"><path d="M0 0 L6 3.4 L6 -2.6 L0 -6 Z"/><animateMotion dur="1.8s" repeatCount="indefinite" path="M126 128 C112 104 92 140 88 168"/><animate attributeName="opacity" values="0;1;1;0" keyTimes="0;.15;.8;1" dur="1.8s" repeatCount="indefinite"/></g>
          <g class="sheet"><path d="M0 0 L6 3.4 L6 -2.6 L0 -6 Z"/><animateMotion dur="1.8s" begin=".6s" repeatCount="indefinite" path="M130 122 C118 96 96 130 89 168"/><animate attributeName="opacity" values="0;1;1;0" keyTimes="0;.15;.8;1" dur="1.8s" begin=".6s" repeatCount="indefinite"/></g>
          <g class="sheet"><path d="M0 0 L6 3.4 L6 -2.6 L0 -6 Z"/><animateMotion dur="1.8s" begin="1.2s" repeatCount="indefinite" path="M122 134 C108 110 90 146 87 168"/><animate attributeName="opacity" values="0;1;1;0" keyTimes="0;.15;.8;1" dur="1.8s" begin="1.2s" repeatCount="indefinite"/></g>
          <ellipse class="bin-shadow" cx="88" cy="188" rx="14" ry="6"/>
          <path class="bin-body" d="M78 169 L80.5 186 A7.5 3.6 0 0 0 95.5 186 L98 169 Z"/>
          <path class="bin-rib" d="M83.5 173 L84.5 185 M88 174 V186 M92.5 173 L91.5 185"/>
          <ellipse class="bin-mouth" cx="88" cy="169" rx="10" ry="4.6"/>
          <g class="bin-lid"><ellipse cx="88" cy="166" rx="10.5" ry="4.8"/><rect x="85.5" y="161.8" width="5" height="2.2" rx="1"/>
            <animateTransform attributeName="transform" type="rotate" values="0 77.5 166;-28 77.5 166;-28 77.5 166;0 77.5 166" keyTimes="0;.2;.75;1" dur="1.8s" repeatCount="indefinite"/></g>
        </g>
      </svg>
      '''
doc.t = t[:a] + new + t[b:]

# texto de debajo: subtarea con barra fina
rep('<div class="sc-task" id="scTask">Preparando el análisis…</div>\n    <div class="sc-sub" id="scCount"></div>',
    '<div class="sc-task" id="scTask">Preparando el análisis…</div>\n    <div class="sc-subtask" id="scSubtask"><span id="scSubTxt"></span><i><b id="scSubBar"></b></i></div>\n    <div class="sc-sub" id="scCount"></div>')

# fases y lógica
rep("const SC_TITLE = {update:'Aplicando cambios', pentest:'Revisión de seguridad', 'pentest-lan':'Analizando la red local', clean:'Liberando espacio', '':'Analizando el equipo'};",
    "const SC_TITLE = {update:'Aplicando cambios', fix:'Aplicando ajustes de seguridad', pentest:'Revisión de seguridad', 'pentest-lan':'Analizando la red local', clean:'Liberando espacio', '':'Analizando el equipo'};\n"
    "const SC_SCENES = ['scan','update','winupdate','clean','fix','restore','done'];\n"
    "const SC_COLOR = {scan:'34,211,238', update:'56,189,248', winupdate:'56,189,248', clean:'167,139,250', fix:'52,211,153', restore:'251,191,36', done:'52,211,153'};\n"
    "function scScene(m){ const el = $('#scanner'); if (!el || SC.scene === m) return; SC.scene = m; SC_SCENES.forEach(s => el.classList.toggle('scene-'+s, s === m)); SC.rgb = SC_COLOR[m] || SC_COLOR.scan; el.style.setProperty('--mc', 'rgb('+SC.rgb+')'); }\n"
    "const cap = s => String(s||'').charAt(0).toUpperCase() + String(s||'').slice(1);\n"
    "function scDots(total, done, cur){\n"
    "  const g = $('#flDots'); if (!g) return; total = Math.min(total||0, 36);\n"
    "  if (g.childNodes.length !== total) { let h = ''; for (let i = 0; i < total; i++) { const a = -Math.PI/2 + i*2*Math.PI/Math.max(total,1); h += `<circle cx=\"${(50+40*Math.cos(a)).toFixed(2)}\" cy=\"${(50+40*Math.sin(a)).toFixed(2)}\" r=\"2.6\"/>`; } g.innerHTML = h; }\n"
    "  [...g.childNodes].forEach((c, i) => c.setAttribute('class', i < done ? 'dot ok' : (cur.includes(i) ? 'dot run' : 'dot')));\n"
    "}")

rep("      x.fillStyle = Math.random()<.04 ? 'rgba(167,139,250,.9)' : 'rgba(45,212,238,'+(0.25+Math.random()*0.5)+')';",
    "      x.fillStyle = Math.random()<.035 ? 'rgba(255,255,255,.85)' : 'rgba('+(SC.rgb||'45,212,238')+','+(0.22+Math.random()*0.5)+')';")
rep("    x.fillStyle = 'rgba(31,41,69,.16)'; x.fillRect(0,0,SC.w,SC.h);",
    "    x.fillStyle = 'rgba(8,12,22,.18)'; x.fillRect(0,0,SC.w,SC.h);")

# consola: hora tenue + mensaje, con estilos por tipo
rep("  lines.forEach(l => { const d = document.createElement('div'); d.className = 'l-'+l.l; d.textContent = `${l.t}  ${l.m}`; box.appendChild(d); });\n  while (box.childNodes.length > 400)",
    "  lines.forEach(l => { const d = document.createElement('div'); d.className = 'l-'+l.l; const t = document.createElement('span'); t.className = 'tm'; t.textContent = l.t; const m = document.createElement('span'); m.className = 'msg'; m.textContent = l.m; d.append(t, m); box.appendChild(d); });\n  while (box.childNodes.length > 600)")

old_upd = t[t.index('function updateScanner(st, wasBusy){'):t.index('function closeScanner(){')]
new_upd = r"""function updateScanner(st, wasBusy){
  if (st.phase === 'refresh') return; // refresco ligero en segundo plano: sin ventana
  if (st.busy && !wasBusy && !SC.userClosed) scanner(true);
  if (!st.busy) { SC.userClosed = false; if (SC.on) { scFinish(st); } return; }
  if (!SC.on) return;
  const phase = st.phase || '';
  const act = st.act || ({clean:'clean', fix:'fix', update:'update'}[phase] || 'scan');
  scScene(act);
  $('#scTag').textContent = SC_TITLE[phase] || 'Procesando';
  $('#scTermHd').textContent = 'Consola en vivo · ' + (SC_TITLE[phase]||'').toLowerCase();
  const [v, m] = st.prog || [0,0];
  const pct = m ? Math.round(100*v/m) : null;
  const ring = $('#scRing'), C = 2*Math.PI*128;
  if (pct === null) { $('#scPct').textContent = '•••'; $('#scPct').style.fontSize='30px'; $('#scPctL').textContent=''; ring.setAttribute('stroke-dasharray', `${C*0.25} ${C}`); ring.style.animation='sweep 1.4s linear infinite'; }
  else { $('#scPct').textContent = pct; $('#scPct').style.fontSize=''; $('#scPctL').textContent='%'; ring.style.animation=''; ring.setAttribute('stroke-dasharray', `${Math.max(1,C*pct/100)} ${C}`); }
  const scanMode = act === 'scan';
  const steps = st.steps || 0, step = st.step || 0, done = st.done || [], running = st.running || [], queue = st.queue || [];
  // tarea principal y subtarea
  $('#scTask').textContent = scanMode ? 'Analizando el equipo' : (st.item || st.status || 'Trabajando…');
  const sp = typeof st.subPct === 'number' ? st.subPct : -1;
  $('#scSubTxt').textContent = st.sub || (scanMode ? (running.length ? 'Comprobando ' + running.join(', ') : 'Preparando…') : '');
  $('#scSubtask').classList.toggle('on', !!(st.sub || scanMode));
  $('#scSubtask').classList.toggle('ind', sp < 0);
  $('#scSubBar').style.width = (sp < 0 ? 30 : sp) + '%';
  // barra de la pantalla: porcentaje real de la subtarea o, si no hay, del conjunto
  const bar = sp >= 0 ? sp : (scanMode ? null : (steps ? Math.round(100*done.length/steps) : null));
  const fill = $('#scrFill'); if (fill) fill.setAttribute('width', bar === null ? 0 : (76*bar/100).toFixed(1));
  $('#scanner').classList.toggle('bar-ind', sp < 0);
  $('#scCount').textContent = scanMode ? (steps ? `${done.length} de ${steps} comprobaciones` : '') : (steps ? `Elemento ${Math.min(step+1, steps)} de ${steps}` : 'Trabajo en segundo plano…');
  // puntos del suelo: uno por comprobación o por elemento
  const cur = scanMode ? running.map((_, i) => done.length + i) : [step];
  scDots(steps, done.length, cur);
  // fichas: hecho ✓ / en curso / en espera
  let chips = [];
  if (scanMode) chips = [...done.map(n => ['ok', n]), ...running.map(n => ['run', n])];
  else chips = queue.map((n, i) => [i < done.length ? 'ok' : (i === step && act !== 'restore' ? 'run' : 'wait'), n]);
  const icoB = {ok:'<svg viewBox="0 0 16 16"><path d="m4 8.4 2.6 2.6L12 5.4"/></svg>', run:'<i class="spin"></i>', wait:'<i class="wt"></i>'};
  const view = chips.length > 9 ? chips.filter(c => c[0] !== 'ok').slice(0, 7).concat(chips.filter(c => c[0] === 'ok').slice(-2)) : chips;
  $('#scBlips').innerHTML = view.map(([k, n]) => `<span class="blip b-${k}">${icoB[k]}${esc(cap(n))}</span>`).join('') + (chips.length > view.length ? `<span class="blip b-more">+${chips.length - view.length}</span>` : '');
}
function scFinish(st){
  scScene('done');
  $('#scRing').setAttribute('stroke-dasharray', `${2*Math.PI*128} ${2*Math.PI*128}`);
  $('#scPct').textContent = '100'; $('#scPct').style.fontSize=''; $('#scPctL').textContent='%';
  $('#scTag').textContent = 'Completado'; $('#scTask').textContent = st.result || 'Proceso terminado.';
  $('#scSubtask').classList.remove('on'); $('#scCount').textContent = '';
  const f = $('#scrFill'); if (f) f.setAttribute('width', 76);
  scDots(SC.lastSteps || 0, 999, []);
  $('#scBlips').innerHTML = `<span class="blip b-ok"><svg viewBox="0 0 16 16"><path d="m4 8.4 2.6 2.6L12 5.4"/></svg>Terminado</span>`;
  setTimeout(() => { scanner(false); SC.scene = ''; $('#scLog').innerHTML=''; }, 2600);
}
"""
rep(old_upd, new_upd)
# recordar cuántos puntos había para pintarlos en verde al terminar
rep("  const steps = st.steps || 0, step = st.step || 0,", "  SC.lastSteps = st.steps || SC.lastSteps; const steps = st.steps || 0, step = st.step || 0,")
rep("  if (show) { $('#scHost').textContent = (S.init && S.init.computer || '') ; scStart(); } else scStop();",
    "  if (show) { $('#scHost').textContent = (S.init && S.init.computer || '') ; if (!SC.scene) scScene('scan'); scStart(); } else scStop();")
