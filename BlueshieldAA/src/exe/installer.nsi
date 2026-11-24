; Instalador de BlueShieldAA (NSIS, Unicode)
Unicode true
SetCompressor /SOLID lzma
!include "MUI2.nsh"
!include "x64.nsh"

Name "BlueShieldAA ${VERSION}"
OutFile "${OUT}"
InstallDir "$PROGRAMFILES64\BlueShieldAA"
RequestExecutionLevel admin
BrandingText "BlueShieldAA ${VERSION}"
VIProductVersion "${VERSION}.0"
VIAddVersionKey /LANG=3082 "ProductName" "BlueShieldAA"
VIAddVersionKey /LANG=3082 "FileDescription" "Instalador de BlueShieldAA"
VIAddVersionKey /LANG=3082 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=3082 "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=3082 "CompanyName" "BlueShieldAA"
VIAddVersionKey /LANG=3082 "LegalCopyright" "BlueShieldAA"

!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\BlueShieldAA.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Abrir BlueShieldAA"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Spanish"

!define UNINST "Software\Microsoft\Windows\CurrentVersion\Uninstall\BlueShieldAA"

!macro QuitarTarea NOMBRE
  nsExec::Exec '"$SYSDIR\schtasks.exe" /Delete /TN "\BlueShieldAA\${NOMBRE}" /F'
!macroend

Function CerrarApp
  StrCpy $1 0
  bucle:
    FindWindow $0 "webview" "BlueShieldAA"
    StrCmp $0 0 fin
    SendMessage $0 0x0010 0 0 /TIMEOUT=2000
    Sleep 500
    IntOp $1 $1 + 1
    IntCmp $1 20 0 bucle 0
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "BlueShieldAA sigue abierto (puede que esté terminando una tarea). Ciérralo y pulsa Reintentar." IDRETRY bucle
    Abort
  fin:
FunctionEnd

Function un.CerrarApp
  StrCpy $1 0
  bucle:
    FindWindow $0 "webview" "BlueShieldAA"
    StrCmp $0 0 fin
    SendMessage $0 0x0010 0 0 /TIMEOUT=2000
    Sleep 500
    IntOp $1 $1 + 1
    IntCmp $1 20 0 bucle 0
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "BlueShieldAA sigue abierto. Ciérralo y pulsa Reintentar." IDRETRY bucle
    Abort
  fin:
FunctionEnd

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "BlueShieldAA necesita Windows 10 u 11 de 64 bits."
    Abort
  ${EndIf}
  SetRegView 64
FunctionEnd

Section "BlueShieldAA" SecMain
  SetShellVarContext all
  ; Si BlueShieldAA está abierto se le pide que se cierre (mensaje normal de Windows)
  Call CerrarApp
  ; Quita las tareas programadas conocidas de la 3.x (la 4.x no las usa). Solo este equipo.
  !insertmacro QuitarTarea "Senuelos"
  !insertmacro QuitarTarea "Vigilancia"
  !insertmacro QuitarTarea "Ventana"
  !insertmacro QuitarTarea "Ordenes"
  !insertmacro QuitarTarea "Sincronizar"
  !insertmacro QuitarTarea "Agente"
  !insertmacro QuitarTarea "Nocturna"

  ; El guardián anti-ransomware (si está activado) se para para poder sustituir el programa
  nsExec::Exec '"$SYSDIR\schtasks.exe" /End /TN "\BlueShieldAA\Guardian"'
  Sleep 1500

  SetOutPath "$INSTDIR"
  File "/oname=BlueShieldAA.exe" "${EXE}"
  File "/oname=WebView2Loader.dll" "${DLL}"
  File "/oname=reglas-analisis.json" "${RULES}"
  File "/oname=sandbox-monitor.ps1" "${MONITOR}"
  File "/oname=desbloquear.cmd" "${UNLOCK}"
  WriteUninstaller "$INSTDIR\Desinstalar.exe"

  CreateShortcut "$SMPROGRAMS\BlueShieldAA.lnk" "$INSTDIR\BlueShieldAA.exe"
  CreateShortcut "$DESKTOP\BlueShieldAA.lnk" "$INSTDIR\BlueShieldAA.exe"

  WriteRegStr HKLM "${UNINST}" "DisplayName" "BlueShieldAA"
  WriteRegStr HKLM "${UNINST}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST}" "Publisher" "BlueShieldAA"
  WriteRegStr HKLM "${UNINST}" "DisplayIcon" "$INSTDIR\BlueShieldAA.exe"
  WriteRegStr HKLM "${UNINST}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST}" "UninstallString" '"$INSTDIR\Desinstalar.exe"'
  WriteRegStr HKLM "${UNINST}" "QuietUninstallString" '"$INSTDIR\Desinstalar.exe" /S'
  WriteRegDWORD HKLM "${UNINST}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST}" "NoRepair" 1
  ; Si el guardián estaba activado vuelve a arrancar con la versión nueva (si no existe, no hace nada)
  nsExec::Exec '"$SYSDIR\schtasks.exe" /Run /TN "\BlueShieldAA\Guardian"'
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  SetRegView 64
  Call un.CerrarApp
  ; Anti-ransomware: quita la tarea del guardián, la contención (si la hubiera) y los documentos trampa
  ExecWait '"$INSTDIR\BlueShieldAA.exe" --desinstalar'
  Delete "$INSTDIR\BlueShieldAA.exe"
  Delete "$INSTDIR\WebView2Loader.dll"
  Delete "$INSTDIR\reglas-analisis.json"
  Delete "$INSTDIR\sandbox-monitor.ps1"
  Delete "$INSTDIR\desbloquear.cmd"
  Delete "$INSTDIR\Desinstalar.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\BlueShieldAA.lnk"
  Delete "$DESKTOP\BlueShieldAA.lnk"
  DeleteRegKey HKLM "${UNINST}"
  ; Los datos (C:\ProgramData\BlueShieldAA) se conservan: historial, cuarentena e informes.
SectionEnd
