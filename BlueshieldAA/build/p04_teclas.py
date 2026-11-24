# F5 / Ctrl+R recargarían la página interna y la ventana se quedaría en blanco.
rep("document.addEventListener('contextmenu', e => { if (!e.target.closest('input,textarea')) e.preventDefault(); });",
    "document.addEventListener('contextmenu', e => { if (!e.target.closest('input,textarea')) e.preventDefault(); });\ndocument.addEventListener('keydown', e => { if (e.key === 'F5' || (e.ctrlKey && e.key.toLowerCase() === 'r') || (e.ctrlKey && e.key.toLowerCase() === 'p')) e.preventDefault(); }, true);")
