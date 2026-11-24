# El logo de la barra lateral va incrustado (antes lo ponía el programa al arrancar).
import base64, os
_png = open(os.path.join(os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else 'build', 'logo.png'), 'rb').read()
rep('<img src="/*LOGOSRC*/"', '<img src="data:image/png;base64,' + base64.b64encode(_png).decode() + '"')
