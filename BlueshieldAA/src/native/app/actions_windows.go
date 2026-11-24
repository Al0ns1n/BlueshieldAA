//go:build windows

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func psDo(e *Engine, script string, timeout time.Duration) error {
	out, err := runPSStream(e, script+"\n'BSOK'", timeout)
	if err != nil {
		return err
	}
	if !strings.Contains(out, "BSOK") {
		msg := strings.TrimSpace(out)
		if msg == "" {
			msg = "Windows no confirmó el cambio"
		}
		return fmt.Errorf("%s", firstLine(msg))
	}
	return nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

func registerActions(e *Engine) {
	need := func(f func(e *Engine, it *Item) (string, error)) Action {
		return func(e *Engine, it *Item) (string, error) {
			if !isAdmin() {
				return "", fmt.Errorf("hace falta abrir BlueShieldAA con permisos de administrador")
			}
			return f(e, it)
		}
	}

	e.AddAction("winget", func(e *Engine, it *Item) (string, error) { return wingetUpgrade(e, it, e.TakeFlag("cerrar:"+it.ID)) })
	e.AddAction("winupdate", need(func(e *Engine, it *Item) (string, error) {
		script := `$s=New-Object -ComObject Microsoft.Update.Session; $q=$s.CreateUpdateSearcher()
$r=$q.Search("UpdateID='` + strings.ReplaceAll(it.Arg, "'", "") + `'"); if($r.Updates.Count -eq 0){'BSOK'; exit}
$c=New-Object -ComObject Microsoft.Update.UpdateColl; foreach($u in $r.Updates){ if(-not $u.EulaAccepted){$u.AcceptEula()}; [void]$c.Add($u) }
'Descargando la actualización…'; $d=$s.CreateUpdateDownloader(); $d.Updates=$c; [void]$d.Download()
'Instalando la actualización…'; $i=$s.CreateUpdateInstaller(); $i.Updates=$c; $x=$i.Install()
if($x.ResultCode -eq 2 -or $x.ResultCode -eq 3){ if($x.RebootRequired){'REBOOT'}; 'BSOK' } else { 'Código de resultado de Windows Update: '+$x.ResultCode }`
		e.SetSub("Descargando e instalando con Windows Update", -1)
		out, err := runPSStream(e, script, 60*time.Minute)
		if err != nil {
			return "", err
		}
		if !strings.Contains(out, "BSOK") {
			return "", fmt.Errorf("%s", firstLine(out))
		}
		if strings.Contains(out, "REBOOT") {
			it.Reboot = true
			return "Pendiente", nil
		}
		return "Actualizado", nil
	}))

	e.AddAction("defsig", func(e *Engine, it *Item) (string, error) {
		mp := filepath.Join(os.Getenv("ProgramFiles"), "Windows Defender", "MpCmdRun.exe")
		e.Cmd("MpCmdRun.exe -SignatureUpdate")
		e.SetSub("Descargando las firmas del antivirus", -1)
		out, code, err := runExeStream(e, 15*time.Minute, mp, "-SignatureUpdate")
		if err != nil {
			return "", err
		}
		if code != 0 {
			return "", fmt.Errorf("no se pudieron actualizar las firmas: %s", firstLine(out))
		}
		return "Al día", nil
	})
	e.AddAction("cfa", need(func(e *Engine, it *Item) (string, error) {
		return "", psDo(e, `Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop`, time.Minute)
	}))
	e.AddAction("firewall", need(func(e *Engine, it *Item) (string, error) {
		p := it.Arg
		if p == "" {
			p = "Domain,Private,Public"
		}
		return "", psDo(e, `Set-NetFirewallProfile -Profile `+p+` -Enabled True -ErrorAction Stop`, time.Minute)
	}))
	e.AddAction("smb1", need(func(e *Engine, it *Item) (string, error) {
		err := psDo(e, `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null`, 5*time.Minute)
		return "", err
	}))
	e.AddAction("rdpnla", need(func(e *Engine, it *Item) (string, error) {
		return "", psDo(e, `Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 -Type DWord -ErrorAction Stop`, time.Minute)
	}))
	e.AddAction("rdpoff", need(func(e *Engine, it *Item) (string, error) {
		return "", psDo(e, `Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1 -Type DWord -ErrorAction Stop`, time.Minute)
	}))
	e.AddAction("guestoff", need(func(e *Engine, it *Item) (string, error) {
		return "", psDo(e, `Get-LocalUser | Where-Object{$_.SID.Value -like '*-501'} | Disable-LocalUser -ErrorAction Stop`, time.Minute)
	}))
	e.AddAction("uac", need(func(e *Engine, it *Item) (string, error) {
		err := psDo(e, `$k='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-ItemProperty $k -Name EnableLUA -Value 1 -Type DWord -ErrorAction Stop
Set-ItemProperty $k -Name ConsentPromptBehaviorAdmin -Value 5 -Type DWord -ErrorAction Stop`, time.Minute)
		if err != nil {
			return "", err
		}
		return "Pendiente", nil
	}))
	e.AddAction("reboot", need(func(e *Engine, it *Item) (string, error) {
		e.Cmd("shutdown /r /t 300")
		_, _, err := runExeStream(e, time.Minute, filepath.Join(sysDir(), "shutdown.exe"), "/r", "/t", "300", "/c", "BlueShieldAA: el equipo se reiniciará en 5 minutos para terminar de aplicar las actualizaciones. Guarda tu trabajo. Para cancelarlo: shutdown /a")
		if err != nil {
			return "", err
		}
		return "Pendiente", nil
	}))
	e.AddAction("open", func(e *Engine, it *Item) (string, error) {
		if strings.HasPrefix(it.Arg, "ms-windows-store:") {
			shellOpen(it.Arg, "")
		} else {
			openURL(it.Arg)
		}
		return "Abierto", nil
	})
	e.AddAction("blockip", need(func(e *Engine, it *Item) (string, error) {
		if net.ParseIP(it.Arg) == nil {
			return "", fmt.Errorf("dirección no válida")
		}
		name := "BlueShieldAA - bloqueo " + it.Arg
		return "", psDo(e, `New-NetFirewallRule -DisplayName `+psq(name)+` -Direction Inbound -Action Block -RemoteAddress `+psq(it.Arg)+` -Profile Any -ErrorAction Stop | Out-Null`, time.Minute)
	}))
	e.AddAction("pentestfix", need(func(e *Engine, it *Item) (string, error) {
		fix, ok := hardFixes[it.Arg]
		if !ok {
			return "", fmt.Errorf("no hay corrección automática para esto")
		}
		if err := psDo(e, fix, 5*time.Minute); err != nil {
			return "", err
		}
		if it.Reboot {
			return "Pendiente", nil
		}
		return "Al día", nil
	}))
	e.AddAction("restorepoint", need(func(e *Engine, it *Item) (string, error) {
		e.SetSub("Guardando una copia del estado de Windows", -1)
		// Windows solo deja crear uno cada 24 h salvo que se cambie la frecuencia
		return "", psDo(e, `Enable-ComputerRestore -Drive "$env:SystemDrive\"
New-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -Name SystemRestorePointCreationFrequency -Value 0 -PropertyType DWord -Force | Out-Null
Checkpoint-Computer -Description 'BlueShieldAA antes de cambios' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop`, 10*time.Minute)
	}))
	e.AddAction("clean", cleanJunk)
	e.AddAction("acceptchange", func(e *Engine, it *Item) (string, error) {
		var base map[string]bool
		bp := e.St.Path("base-persistencia.json")
		_ = readJSON(bp, &base)
		if base == nil {
			base = map[string]bool{}
		}
		base[it.Arg] = true
		return "Al día", writeJSON(bp, base)
	})
}

var hardFixes = map[string]string{
	"wdigest":  `Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0 -Type DWord -ErrorAction Stop`,
	"lmcompat": `Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 3 -Type DWord -ErrorAction Stop`,
	"llmnr":    `$k='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; if(-not (Test-Path $k)){New-Item $k -Force | Out-Null}; Set-ItemProperty $k -Name EnableMulticast -Value 0 -Type DWord -ErrorAction Stop`,
	"ppl":      `Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord -ErrorAction Stop`,
	"autorun":  `$k='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; if(-not (Test-Path $k)){New-Item $k -Force | Out-Null}; Set-ItemProperty $k -Name NoDriveTypeAutoRun -Value 255 -Type DWord -ErrorAction Stop`,
	"psv2":     `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction Stop | Out-Null`,
}

func wingetErr(out string) string {
	lo := strings.ToLower(out)
	switch {
	case strings.Contains(lo, "0x8a15002b") || strings.Contains(lo, "no applicable upgrade") || strings.Contains(lo, "no se encontró ninguna actualización"):
		return "no hay una versión aplicable para este equipo"
	case strings.Contains(lo, "in use") || strings.Contains(lo, "en uso"):
		return "el programa está abierto; ciérralo y vuelve a intentarlo"
	case strings.Contains(lo, "hash"):
		return "la descarga no coincide con la huella publicada (se ha cancelado por seguridad)"
	}
	return firstLine(lastLines(cleanConsole(out), 2))
}

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, " ")
}

type procInfo struct {
	ID      int    `json:"id"`
	Name    string `json:"n"`
	Product string `json:"p"`
	Desc    string `json:"d"`
	Path    string `json:"x"`
}

// openProcs: procesos abiertos que pertenecen al programa (por producto, descripción o nombre).
func openProcs(name string) []procInfo {
	key := NameKey(name)
	if key == "" {
		return nil
	}
	var l []procInfo
	for _, p := range ProcList(false) {
		if p.Path == "" {
			continue
		}
		m := FileMeta(p.Path)
		l = append(l, procInfo{ID: p.PID, Name: strings.TrimSuffix(p.Name, ".exe"), Product: m.Product, Desc: m.Desc, Path: p.Path})
	}
	me := os.Getpid()
	var out []procInfo
	for _, p := range l {
		if p.ID == me || strings.Contains(strings.ToLower(p.Path), `\windows\`) {
			continue
		}
		if ProcMatches(key, p.Product, p.Desc, p.Name+".exe") {
			out = append(out, p)
		}
	}
	return out
}

func procNames(l []procInfo) string {
	seen := map[string]bool{}
	var n []string
	for _, p := range l {
		if !seen[p.Name] {
			seen[p.Name] = true
			n = append(n, p.Name)
		}
	}
	return strings.Join(n, ", ")
}

// closeGracefully pide a los procesos que se cierren como si se pulsara la X (nunca a la fuerza).
func closeGracefully(e *Engine, l []procInfo) bool {
	ids := []string{}
	for _, p := range l {
		ids = append(ids, fmt.Sprint(p.ID))
	}
	e.Cmd("Cerrando con normalidad: %s", procNames(l))
	_, _ = runPS(`foreach($i in @(`+strings.Join(ids, ",")+`)){ $p=Get-Process -Id $i -ErrorAction SilentlyContinue; if($p){ [void]$p.CloseMainWindow() } }
$t=0; while($t -lt 20 -and (Get-Process -Id @(`+strings.Join(ids, ",")+`) -ErrorAction SilentlyContinue)){ Start-Sleep -Milliseconds 500; $t++ }`, time.Minute)
	for _, p := range l {
		if _, err := os.FindProcess(p.ID); err == nil {
			if out, _ := runPS(fmt.Sprintf(`if(Get-Process -Id %d -ErrorAction SilentlyContinue){'SIGUE'}`, p.ID), 15*time.Second); strings.Contains(out, "SIGUE") {
				return false
			}
		}
	}
	return true
}

// installedVersion: versión que winget ve instalada ahora mismo.
func installedVersion(wg, id string) string {
	out, _, err := runExe(2*time.Minute, wg, "list", "--id", id, "--exact", "--accept-source-agreements", "--disable-interactivity")
	if err != nil {
		return ""
	}
	for _, p := range ParseWingetTable(out) {
		if strings.EqualFold(p.ID, id) {
			return p.Version
		}
	}
	return ""
}

func wingetUpgrade(e *Engine, it *Item, closeFirst bool) (string, error) {
	wg := wingetPath()
	if wg == "" {
		return "", fmt.Errorf("no se encuentra winget")
	}
	// 1) ¿Está abierto? Sin cerrarlo, la mayoría de instaladores fallan (como OBS con el código 6).
	e.SetSub("Comprobando si "+it.Name+" está abierto", -1)
	if procs := openProcs(it.Name); len(procs) > 0 {
		if !closeFirst {
			it.Alt, it.AltLabel = "closeupdate", "Cerrar y actualizar"
			e.St.AddHist(HistEntry{Name: it.Name, WingetID: it.Arg, Source: "manual", From: it.Current, To: it.Available, Result: "Error"})
			return "", fmt.Errorf("%s está abierto (%s). Ciérralo y vuelve a intentarlo, o pulsa «Cerrar y actualizar»", it.Name, procNames(procs))
		}
		e.SetSub("Cerrando "+it.Name, -1)
		if !closeGracefully(e, procs) {
			return "", fmt.Errorf("%s no se ha cerrado (puede tener algo sin guardar). Ciérralo a mano y vuelve a intentarlo", it.Name)
		}
	}
	args := []string{"upgrade", "--id", it.Arg, "--exact", "--silent", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity", "--include-unknown"}
	var res WingetResult
	var out string
	for attempt := 1; attempt <= 2; attempt++ {
		e.Cmd("winget %s", strings.Join(args, " "))
		e.SetSub("Buscando el paquete", -1)
		o, code, err := runExeStream(e, 30*time.Minute, wg, args...)
		if err != nil {
			return "", err
		}
		out = o
		res = InterpretWinget(out, code)
		if res.OK || !res.Retry || attempt == 2 {
			break
		}
		e.Log("warn", "Hay otra instalación en marcha; se reintenta dentro de 60 s…")
		e.SetSub("Esperando a que termine otra instalación", -1)
		time.Sleep(60 * time.Second)
	}
	// 2) Comprobación real: ¿ha cambiado la versión instalada?
	if res.OK {
		e.SetSub("Comprobando la versión instalada", -1)
		now := installedVersion(wg, it.Arg)
		if now != "" && it.Available != "" && it.Available != "-" && CompareVersions(now, it.Available) < 0 && !res.Reboot {
			res.OK = false
			res.Message = fmt.Sprintf("El instalador terminó sin error, pero la versión instalada sigue siendo %s (se esperaba %s).", now, it.Available)
		} else if now != "" {
			it.Current = now
			e.Out("Versión instalada ahora: " + now)
		}
	}
	result := "OK"
	if !res.OK {
		result = "Error"
	}
	e.St.AddHist(HistEntry{Name: it.Name, WingetID: it.Arg, Source: "manual", From: it.Current, To: it.Available, Result: result})
	if !res.OK {
		if res.InUse {
			it.Alt, it.AltLabel = "closeupdate", "Cerrar y actualizar"
		}
		return "", fmt.Errorf("%s", res.Message)
	}
	it.Alt, it.AltLabel = "", ""
	if res.Reboot {
		it.Reboot = true
		return "Pendiente", nil
	}
	return "Actualizado", nil
}
