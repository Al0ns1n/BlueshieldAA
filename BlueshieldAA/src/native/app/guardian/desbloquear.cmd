@echo off
rem Quita el modo contencion del anti-ransomware de BlueShieldAA aunque la ventana no abra.
rem Ejecutalo como administrador (clic derecho - Ejecutar como administrador).
net session >nul 2>&1
if errorlevel 1 (
  echo Hay que ejecutar este archivo como administrador: clic derecho - Ejecutar como administrador.
  pause
  exit /b 1
)
echo Parando el guardian...
schtasks /End /TN "\BlueShieldAA\Guardian" >nul 2>&1
echo Devolviendo la red, los servicios y la ejecucion normal de programas...
"%~dp0BlueShieldAA.exe" --liberar
netsh advfirewall firewall delete rule name="BlueShieldAA-Contencion-Salida" >nul 2>&1
netsh advfirewall firewall delete rule name="BlueShieldAA-Contencion-Entrada" >nul 2>&1
echo.
echo Listo. El equipo ya no esta en contencion.
echo El guardian vuelve a vigilar al reiniciar Windows (o desde BlueShieldAA - Anti-ransomware).
echo Si fue un ataque real, revisa el equipo con TI antes de seguir trabajando.
pause
