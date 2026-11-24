# BlueShieldAA - observador del entorno aislado (Windows Sandbox)
#
# Este script SOLO se ejecuta dentro de Windows Sandbox, una máquina desechable sin red que
# Windows borra entera al cerrarse. Abre el archivo que se quiere analizar y apunta lo que
# pasa: procesos, archivos, inicio automático, documentos señuelo y capturas de pantalla.
# Escribe el resultado en C:\bs\out (carpeta compartida con BlueShieldAA) y apaga el entorno.

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$in = 'C:\bs\in'; $out = 'C:\bs\out'
$cfg = Get-Content "$in\config.json" -Raw | ConvertFrom-Json
function Paso($s) { Add-Content -Path "$out\progreso.txt" -Value $s -Encoding UTF8 }
Paso 'arrancado'

Add-Type -AssemblyName System.Windows.Forms, System.Drawing

# --- Documentos señuelo: si algo los cifra, borra o renombra, es ransomware ---
$docs = [Environment]::GetFolderPath('MyDocuments')
$pics = [Environment]::GetFolderPath('MyPictures')
1..10 | ForEach-Object {
    Set-Content -Path "$docs\Presupuesto_$_.docx" -Value ("Documento de prueba de BlueShieldAA $_ " + ('lorem ipsum ' * 40))
    Set-Content -Path "$pics\Vacaciones_$_.jpg" -Value ('x' * 4096)
}
$senuelos = @{}
Get-ChildItem $docs, $pics -File | ForEach-Object { $senuelos[$_.FullName] = (Get-FileHash $_.FullName -Algorithm MD5).Hash }

# --- Foto inicial ---
$base = @{}; Get-CimInstance Win32_Process | ForEach-Object { $base[[int]$_.ProcessId] = 1 }
$runKeys = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
           'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
function ValoresRun {
    $r = @{}
    foreach ($k in $runKeys) {
        $p = Get-ItemProperty $k
        if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $r["$k\$($_.Name)"] = [string]$_.Value } }
    }
    $r
}
$run0 = ValoresRun
$tareas0 = @{}; Get-ScheduledTask | ForEach-Object { $tareas0[$_.TaskPath + $_.TaskName] = 1 }
$serv0 = @{}; Get-Service | ForEach-Object { $serv0[$_.Name] = 1 }
$startup = [Environment]::GetFolderPath('Startup')

# --- El archivo, en el Escritorio con su nombre original ---
$muestra = Join-Path ([Environment]::GetFolderPath('Desktop')) $cfg.name
Copy-Item "$in\muestra.bin" $muestra -Force
Start-Sleep -Milliseconds 500
$t0 = Get-Date

$procs = @{}
Register-CimIndicationEvent -ClassName Win32_ProcessStartTrace -SourceIdentifier bsInicio
function Vigilar {
    Get-CimInstance Win32_Process | ForEach-Object {
        $id = [int]$_.ProcessId
        if (-not $base[$id]) {
            if (-not $procs[$id]) {
                $procs[$id] = @{ pid = $id; ppid = [int]$_.ParentProcessId; name = [string]$_.Name; cmd = [string]$_.CommandLine; path = [string]$_.ExecutablePath; t = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1) }
            } elseif (-not $procs[$id].cmd -and $_.CommandLine) {
                $procs[$id].cmd = [string]$_.CommandLine; $procs[$id].path = [string]$_.ExecutablePath
            }
        }
    }
    Get-Event -SourceIdentifier bsInicio | ForEach-Object {
        $e = $_.SourceEventArgs.NewEvent; $id = [int]$e.ProcessID
        if (-not $base[$id] -and -not $procs[$id]) {
            $procs[$id] = @{ pid = $id; ppid = [int]$e.ParentProcessID; name = [string]$e.ProcessName; cmd = ''; path = ''; t = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1) }
        }
        Remove-Event -EventIdentifier $_.EventIdentifier
    }
}

$jpeg = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' }
$ep = New-Object System.Drawing.Imaging.EncoderParameters 1
$ep.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter ([System.Drawing.Imaging.Encoder]::Quality), 72L
function Captura($n) {
    $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
    $w = 1100; $h = [int]($b.Height * $w / $b.Width)
    $s = New-Object System.Drawing.Bitmap $bmp, $w, $h
    $f = "$out\captura_{0:D2}.jpg" -f $n
    $s.Save("$f.tmp", $jpeg, $ep); Move-Item "$f.tmp" $f -Force
    $g.Dispose(); $bmp.Dispose(); $s.Dispose()
}

# --- Abrir el archivo como con doble clic ---
Captura 0
$abierto = $true; $errorAbrir = ''
Paso 'abriendo'
try { Start-Process -FilePath $muestra -ErrorAction Stop } catch { $abierto = $false; $errorAbrir = $_.Exception.Message }

$n = 1
while (((Get-Date) - $t0).TotalSeconds -lt [int]$cfg.seconds) {
    Start-Sleep -Milliseconds 600
    Vigilar
    if (((Get-Date) - $t0).TotalSeconds -ge $n * 4) { Captura $n; $n++; Paso ('observando ' + [int]((Get-Date) - $t0).TotalSeconds) }
}
Vigilar
Captura $n
Paso 'recogiendo'

# --- Qué ha cambiado ---
$archivos = @()
$carpetas = [Environment]::GetFolderPath('UserProfile'), $env:ProgramData, "$env:windir\Temp", 'C:\Users\Public', "$env:windir\System32\Tasks"
foreach ($d in $carpetas) {
    Get-ChildItem $d -Recurse -File -Force | Where-Object { $_.LastWriteTime -gt $t0 -and $_.FullName -ne $muestra -and -not $senuelos.ContainsKey($_.FullName) } |
        Select-Object -First 500 | ForEach-Object { $archivos += @{ p = $_.FullName; s = [int64]$_.Length } }
}
$cambiados = 0; $borrados = 0
foreach ($k in $senuelos.Keys) {
    if (-not (Test-Path $k)) { $borrados++ } elseif ((Get-FileHash $k -Algorithm MD5).Hash -ne $senuelos[$k]) { $cambiados++ }
}
$nuevosDocs = @(Get-ChildItem $docs, $pics -File | Where-Object { -not $senuelos.ContainsKey($_.FullName) } | ForEach-Object { $_.Name })
$run1 = ValoresRun; $runNuevos = @()
foreach ($k in $run1.Keys) { if (-not $run0.ContainsKey($k) -or $run0[$k] -ne $run1[$k]) { $runNuevos += @{ k = $k; v = $run1[$k] } } }
$tareasNuevas = @(Get-ScheduledTask | Where-Object { -not $tareas0[$_.TaskPath + $_.TaskName] } | ForEach-Object { $_.TaskPath + $_.TaskName + ' → ' + (($_.Actions | ForEach-Object { ([string]$_.Execute + ' ' + [string]$_.Arguments).Trim() }) -join ' ; ') })
$servNuevos = @(Get-CimInstance Win32_Service | Where-Object { -not $serv0[$_.Name] } | ForEach-Object { $_.Name + ' → ' + $_.PathName })
$inicio = @(Get-ChildItem $startup -File | ForEach-Object { $_.Name })
$defender = @(Get-MpThreatDetection | ForEach-Object { $t = Get-MpThreat -ThreatID $_.ThreatID; [string]$t.ThreatName + ' · ' + (($_.Resources) -join ', ') })

$informe = @{
    name = $cfg.name; seconds = [int]$cfg.seconds; opened = $abierto; openErr = $errorAbrir
    procs = @($procs.Values); files = $archivos; runNew = $runNuevos; tasksNew = $tareasNuevas; svcNew = $servNuevos; startup = $inicio
    decoysChanged = $cambiados; decoysDeleted = $borrados; decoysTotal = $senuelos.Count; newInDocs = $nuevosDocs; defender = $defender; shots = $n + 1
}
$informe | ConvertTo-Json -Depth 5 -Compress | Set-Content -Path "$out\informe.json.tmp" -Encoding UTF8
Move-Item "$out\informe.json.tmp" "$out\informe.json" -Force
Paso 'fin'
Start-Sleep -Seconds 1
Stop-Computer -Force
