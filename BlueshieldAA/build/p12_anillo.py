# Anillo de porcentaje de la ventana de progreso: gira sobre su centro cuando no hay porcentaje
# (antes orbitaba alrededor de una esquina), avanza suave y nunca retrocede en la misma tarea.

t = doc.t
a = t.index("  const ring = $('#scRing'), C = 2*Math.PI*128;\n  if (pct === null)")
b = t.index("\n", t.index("  else { $('#scPct').textContent = pct;", a)) + 1
doc.t = t[:a] + "  scRingTo(pct, (st.phase || '') + '|' + (st.act === 'scan' ? 'scan' : 'run'));\n" + t[b:]
rep("""  $('#scRing').setAttribute('stroke-dasharray', `${2*Math.PI*128} ${2*Math.PI*128}`);
  $('#scPct').textContent = '100'; $('#scPct').style.fontSize=''; $('#scPctL').textContent='%';""",
    """  scRingTo(100, HUD.key, true);""")
rep("const SC_SCENES = ['scan',", r"""const HUD = {key:'', shown:0, target:0, raf:0, t0:0, ind:false};
const HUD_C = 2 * Math.PI * 128;
function scRingReset(){ cancelAnimationFrame(HUD.raf); Object.assign(HUD, {key:'', shown:0, target:0, raf:0, t0:Date.now(), ind:false}); const r = $('#scRing'); if (r) r.setAttribute('stroke-dasharray', `0 ${HUD_C}`); const n = $('#scPct'); if (n) n.textContent = '0'; }
// pct: 0-100 o null (sin porcentaje conocido). key: si cambia la tarea, se empieza de cero.
function scRingTo(pct, key, finish){
  if (key !== HUD.key) { HUD.key = key; HUD.shown = 0; HUD.target = 0; HUD.t0 = Date.now(); }
  const hud = document.querySelector('.isohud');
  HUD.ind = pct === null && !finish;
  if (hud) hud.classList.toggle('ind', HUD.ind);
  HUD.fast = !!finish;
  if (!HUD.ind) HUD.target = finish ? 100 : Math.max(HUD.target, Math.min(100, pct)); // nunca hacia atrás
  if (!HUD.raf) HUD.raf = requestAnimationFrame(scRingFrame);
}
function scRingFrame(){
  HUD.raf = 0;
  const r = $('#scRing'), n = $('#scPct'), l = $('#scPctL'); if (!r || !n) return;
  if (HUD.ind) {
    const s = Math.round((Date.now() - HUD.t0) / 1000);
    r.setAttribute('stroke-dasharray', `${HUD_C * 0.22} ${HUD_C}`);
    n.textContent = s < 60 ? s : Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0'); n.style.fontSize = '24px';
    l.textContent = s < 60 ? 'segundos' : 'min';
  } else {
    const d = HUD.target - HUD.shown;
    HUD.shown = Math.abs(d) < 0.3 ? HUD.target : HUD.shown + d * (HUD.fast ? 0.2 : 0.1) + Math.sign(d) * 0.15;
    r.setAttribute('stroke-dasharray', `${Math.max(0.01, HUD_C * HUD.shown / 100)} ${HUD_C}`);
    n.textContent = Math.round(HUD.shown); n.style.fontSize = ''; l.textContent = '%';
  }
  if (SC.on && (HUD.ind || HUD.shown !== HUD.target)) HUD.raf = requestAnimationFrame(scRingFrame);
}
setInterval(() => { if (SC.on && HUD.ind && !HUD.raf) HUD.raf = requestAnimationFrame(scRingFrame); }, 1000);
const SC_SCENES = ['scan',""")
rep("  if (show) { $('#scHost').textContent = (S.init && S.init.computer || '') ; if (!SC.scene) scScene('scan'); scStart(); } else scStop();",
    "  if (show) { $('#scHost').textContent = (S.init && S.init.computer || '') ; if (!SC.scene) scScene('scan'); if (!SC.on2) scRingReset(); SC.on2 = true; scStart(); } else { scStop(); SC.on2 = false; }")
