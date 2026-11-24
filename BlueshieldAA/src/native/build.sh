#!/usr/bin/env bash
# Compila BlueShieldAA para Windows 64 bits desde Linux y genera el instalador.
# Necesita: go 1.24+, x86_64-w64-mingw32-windres (binutils-mingw-w64), makensis (nsis).
# Antes: python3 build/apply.py (genera app/web/index.html).
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)
VERSION=$(grep -oP 'const AppVersion = "\K[^"]+' app/store.go)
IFS=. read -r V1 V2 V3 <<<"$VERSION"
echo "BlueShieldAA $VERSION"

[ -f app/web/index.html ] || { echo "Falta app/web/index.html: ejecuta antes python3 build/apply.py"; exit 1; }

# Recursos: icono, manifiesto y versión
cd app/rsrc
sed "s/@VERSION4@/$VERSION.0/" app.manifest > app.manifest.out
sed -e "s/@VERSION@/$VERSION/g" -e "s/@V1@/$V1/g" -e "s/@V2@/$V2/g" -e "s/@V3@/$V3/g" app.rc.in > app.rc
x86_64-w64-mingw32-windres --preprocessor=cpp --preprocessor-arg=-P -O coff -i app.rc -o ../rsrc_windows_amd64.syso
rm -f app.rc app.manifest.out
cd ..

# Tests (parte portable) y comprobación del código de Windows
GOFLAGS=-mod=mod GOPROXY=off go test .
GOFLAGS=-mod=mod GOPROXY=off GOOS=windows GOARCH=amd64 go vet .

# Programa
GOFLAGS=-mod=mod GOPROXY=off GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags "-H windowsgui -s -w" -o BlueShieldAA.exe .
echo "Programa: src/native/app/BlueShieldAA.exe ($(du -h BlueShieldAA.exe | cut -f1))"

# Instalador
mkdir -p "$ROOT/src/exe/out2"
makensis -V2 -DVERSION="$VERSION" -DEXE="$PWD/BlueShieldAA.exe" -DICON="$PWD/rsrc/app.ico" \
  -DDLL="$PWD/rsrc/WebView2Loader.dll" -DRULES="$PWD/reglas/reglas-analisis.json" -DMONITOR="$PWD/sandbox/sandbox-monitor.ps1" -DUNLOCK="$PWD/guardian/desbloquear.cmd" \
  -DOUT="$ROOT/src/exe/out2/BlueShieldAA-Setup.exe" "$ROOT/src/exe/installer.nsi"
echo "Instalador: src/exe/out2/BlueShieldAA-Setup.exe"
