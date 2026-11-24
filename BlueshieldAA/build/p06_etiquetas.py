# Etiquetas de estado rediseñadas: icono propio por estado, mejor contraste y mismo alto en
# todas. Se usan en listas, detalle, Panel e Historial.
rep("const pill = s => { const c = CV[STC[s]||'n']; return `<span class=\"st\" style=\"color:${c[1]}\">${esc(s)}</span>`; };",
r"""const STI = {
  'Vulnerable':'<path d="M8 1.6 2.9 3.5v3.9c0 3.2 2.1 6 5.1 7 3-1 5.1-3.8 5.1-7V3.5Z"/><path d="M8 5.2v3.4M8 10.9v.1"/>',
  'Falló':'<circle cx="8" cy="8" r="6.2"/><path d="m5.8 5.8 4.4 4.4m0-4.4-4.4 4.4"/>',
  'Error':'<circle cx="8" cy="8" r="6.2"/><path d="m5.8 5.8 4.4 4.4m0-4.4-4.4 4.4"/>',
  'Actualizar':'<path d="M8 13V3.6M4.3 7.2 8 3.5l3.7 3.7"/><path d="M3.5 13.4h9"/>',
  'Revisar':'<path d="M1.6 8s2.4-4.6 6.4-4.6S14.4 8 14.4 8s-2.4 4.6-6.4 4.6S1.6 8 1.6 8Z"/><circle cx="8" cy="8" r="1.9"/>',
  'Al día':'<circle cx="8" cy="8" r="6.2"/><path d="m5.3 8.2 1.9 1.9 3.6-3.8"/>',
  'Corregida':'<path d="M8 1.6 2.9 3.5v3.9c0 3.2 2.1 6 5.1 7 3-1 5.1-3.8 5.1-7V3.5Z"/><path d="m5.6 8 1.6 1.6 3.1-3.3"/>',
  'Actualizado':'<path d="m2.6 8.4 2.6 2.6 5.3-5.6M7.9 10.9l.2.1 5.3-5.6"/>',
  'Limpio':'<path d="M8 2.2 9.3 6.7 13.8 8 9.3 9.3 8 13.8 6.7 9.3 2.2 8l4.5-1.3Z"/>',
  'Limpiable':'<path d="M3.2 4.6h9.6M6.4 4.6V3h3.2v1.6M4.4 4.6l.6 8.5h6l.6-8.5"/><path d="M6.9 7v4m2.2-4v4"/>',
  'Pendiente':'<circle cx="8" cy="8" r="6.2"/><path d="M8 4.8V8l2.2 1.4"/>',
  'Abierto':'<rect x="2.8" y="7" width="10.4" height="6.6" rx="1.6"/><path d="M5.2 7V5a2.8 2.8 0 0 1 5.4-1"/>',
  'Info':'<circle cx="8" cy="8" r="6.2"/><path d="M8 7.3v3.6M8 5.1v.1"/>',
  'Oculto':'<path d="M2 2l12 12M6.6 3.6A6.8 6.8 0 0 1 8 3.4c4 0 6.4 4.6 6.4 4.6a12 12 0 0 1-1.8 2.3M4 5.1A12 12 0 0 0 1.6 8S4 12.6 8 12.6a6.5 6.5 0 0 0 2.6-.5"/>',
  'Desinstalada':'<circle cx="8" cy="8" r="6.2"/><path d="m5.3 8.2 1.9 1.9 3.6-3.8"/>',
  'Excluida':'<circle cx="8" cy="8" r="6.2"/><path d="m3.6 12.4 8.8-8.8"/>',
  'Al abrir':'<path d="M4 2.8v10.4l8.6-5.2Z"/>',
  'Sin informar':'<circle cx="8" cy="8" r="6.2"/><path d="M6.2 6.3a1.9 1.9 0 1 1 2.6 1.8c-.5.2-.8.6-.8 1.1v.4M8 11.4v.1"/>',
  'Esperando informe':'<circle cx="8" cy="8" r="6.2"/><path d="M8 4.8V8l2.2 1.4"/>'
};
const stIcon = s => `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${STI[s] || STI['Info']}</svg>`;
const pill = s => `<span class="st st-${STC[s]||'n'}">${stIcon(s)}<span>${esc(s)}</span></span>`;""")
rep("const statusCell = it => isExp(it) ? '<span class=\"fire\">Explotada</span>'",
    "const statusCell = it => isExp(it) ? '<span class=\"fire\"><svg viewBox=\"0 0 16 16\" fill=\"currentColor\" aria-hidden=\"true\"><path d=\"M8.6 1.2c.4 2.4-1.6 3.6-2.6 5.1-.6-.7-.8-1.5-.8-2.3C3.6 5.4 2.6 7.3 2.6 9.3c0 3 2.4 5.5 5.4 5.5s5.4-2.4 5.4-5.4c0-3.6-2.6-6.6-4.8-8.2Zm-.4 12.1c-1.4 0-2.4-1-2.4-2.3 0-1.5 1.2-2.3 2-3.4.6 1.3 2.8 2 2.8 3.6 0 1.2-1 2.1-2.4 2.1Z\"/></svg>Explotada</span>'")
rep("""${it.priority==='Alta'?'<span class="tag" style="background:var(--amber-bg);color:var(--amber-ink)">Prioridad alta</span>':''}""",
    """${it.priority==='Alta'?'<span class="tag tg-prio"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 2.2v7.4M8 12.6v.2"/></svg>Prioridad alta</span>':''}""")
