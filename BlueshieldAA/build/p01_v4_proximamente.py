# 4.0: el Panel de empresa vuelve en una 4.x (el anti-ransomware ya ha vuelto: p13). Se dice claramente en vez de
# mostrar botones que no hacen nada.
rep("""<button class="btn sm" onclick="caOpenPanel(); toast('Abriendo el Panel de empresa…')">""",
    """<button class="btn sm" onclick="caOpenPanel()">""")
