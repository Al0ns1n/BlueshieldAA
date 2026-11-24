# Fuentes incrustadas (no dependen de lo que tenga instalado Windows):
#  - Inter (variable, con tamaño óptico): todo el texto.
#  - Space Grotesk: títulos, cifras grandes y ventana de progreso.
#  - JetBrains Mono: consola, versiones y datos técnicos.
import base64, os
_d = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fonts')
def _ff(fam, fn, w):
    b = base64.b64encode(open(os.path.join(_d, fn), 'rb').read()).decode()
    return '@font-face{font-family:"%s";src:url(data:font/woff2;base64,%s) format("woff2");font-weight:%s;font-style:normal;font-display:block}\n' % (fam, b, w)
_css = (_ff('Inter', 'inter-latin-opsz-normal.woff2', '100 900')
      + _ff('Space Grotesk', 'space-grotesk-latin-wght-normal.woff2', '300 700')
      + _ff('Inter Display', 'space-grotesk-latin-wght-normal.woff2', '300 700')
      + _ff('JetBrains Mono', 'jetbrains-mono-latin-wght-normal.woff2', '100 800'))
rep('/*FONTS*/', _css)
rep('--mono:"Cascadia Mono",Consolas,monospace;', '--mono:"JetBrains Mono","Cascadia Mono",Consolas,monospace;--display:"Space Grotesk",Inter,"Segoe UI",sans-serif;')
rep("x.font = '14px \"Cascadia Mono\",monospace';", "x.font = '13px \"JetBrains Mono\",monospace';")
