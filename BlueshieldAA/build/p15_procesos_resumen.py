# 4.2: el resumen de Procesos pasa a ser tarjetas que filtran la lista al pulsarlas.

rep("""  $('#prStats').innerHTML = [['Procesos', d.total, ''], ['A revisar', d.flagged, d.flagged ? 'var(--red-ink)' : ''], ['Sin firmar', d.unsigned, d.unsigned ? 'var(--amber-ink)' : ''], ['Usan la red', d.net, ''], ['Más CPU', top ? `${esc(top.name)} · ${top.cpu} %` : '—', '']]
    .map(([k, v, c]) => `<div class="tstat"><small>${k}</small><b style="${c ? 'color:' + c : ''}">${v}</b></div>`).join('');""",
"""  $('#prStats').innerHTML = prStatsHTML(d, top);""")
rep("  if (PR.view === 'flag') l = l.filter(p => p.flag || p.signed === 'Sin firmar');",
    """  if (PR.view === 'flag') l = l.filter(p => p.flag);
  if (PR.view === 'unsigned') l = l.filter(p => p.signed === 'Sin firmar' || p.signed === 'Firma no válida');
  if (PR.view === 'net') l = [...l.filter(p => p.conns)].sort((a, b) => b.conns - a.conns);""")
rep("function prSetView(v){", r"""function prStatsHTML(d, top){
  const v = PR.view;
  const card = (id, color, icon, label, value, hint, extra) => `<button class="pst ${v === id ? 'on' : ''}" style="--c:${color}" onclick="prSetView('${v === id && id !== 'tree' ? 'tree' : id}')">
      <span class="pst-ic"><i class="ic">${ic(icon)}</i></span><span class="pst-t"><small>${label}</small><b>${value}</b><em>${hint}</em>${extra || ''}</span></button>`;
  const cpu = top ? Math.min(100, top.cpu) : 0;
  return card('tree', 'var(--accent)', 'pc', 'En marcha', d.total, 'procesos ahora mismo')
    + card('flag', d.flagged ? 'var(--red)' : 'var(--green)', d.flagged ? 'alert' : 'check', 'A revisar', d.flagged, d.flagged ? 'merecen un vistazo' : 'nada fuera de lo normal')
    + card('unsigned', d.unsigned ? 'var(--amber)' : 'var(--green)', 'key', 'Sin firmar', d.unsigned, d.unsigned ? 'sin firma del fabricante' : 'todos firmados')
    + card('net', 'var(--vio)', 'net', 'Usan la red', d.net, 'con conexiones')
    + card('cpu', 'var(--amber)', 'bolt', 'Más CPU', top ? esc(top.name) : '—', top ? `${top.cpu.toFixed ? top.cpu.toFixed(1) : top.cpu} % del procesador` : 'sin datos', `<span class="pst-bar"><i style="width:${cpu}%"></i></span>`);
}
function prSetView(v){""")

rep("""      <div class="seg" id="prView"><button data-v="tree" class="on" onclick="prSetView('tree')">Árbol</button><button data-v="flag" onclick="prSetView('flag')">A revisar</button><button data-v="cpu" onclick="prSetView('cpu')">Más CPU</button></div></div>""", "</div>")
