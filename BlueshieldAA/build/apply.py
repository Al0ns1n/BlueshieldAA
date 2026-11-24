#!/usr/bin/env python3
"""Aplica los parches de la interfaz.

Lee orig/native/app/web/index.html (la interfaz recuperada de la 3.11.3), aplica en orden
los scripts build/p*.py y el CSS de build/new.css, y escribe src/native/app/web/index.html.
rep(old, new) exige que 'old' aparezca exactamente una vez.
"""
import glob, os, runpy, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'orig', 'native', 'app', 'web', 'index.html')
DST = os.path.join(ROOT, 'src', 'native', 'app', 'web', 'index.html')

class Doc:
    def __init__(self, t): self.t = t
    def rep(self, old, new):
        n = self.t.count(old)
        if n != 1:
            sys.exit(f'rep: se esperaba 1 coincidencia y hay {n}:\n{old[:200]}')
        self.t = self.t.replace(old, new)

def main():
    d = Doc(open(SRC, encoding='utf-8').read())
    for p in sorted(glob.glob(os.path.join(ROOT, 'build', 'p[0-9]*.py'))):
        runpy.run_path(p, init_globals={'rep': d.rep, 'doc': d})
        print('  aplicado', os.path.basename(p))
    css = os.path.join(ROOT, 'build', 'new.css')
    if os.path.exists(css):
        d.rep('</style>', open(css, encoding='utf-8').read() + '\n</style>')
    os.makedirs(os.path.dirname(DST), exist_ok=True)
    open(DST, 'w', encoding='utf-8').write(d.t)
    print('Interfaz generada:', os.path.relpath(DST, ROOT), f'({len(d.t)//1024} KB)')

if __name__ == '__main__':
    main()
