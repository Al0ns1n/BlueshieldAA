//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ---------- scripts de lectura ----------

const psSecurity = `
$o=@{}
try{$o.av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object{@{name=$_.displayName;state=[int]$_.productState}})}catch{$o.av=@()}
$m=Get-MpComputerStatus
if($m){$o.defPresent=$true;$o.defEnabled=[bool]$m.AntivirusEnabled;$o.defRT=[bool]$m.RealTimeProtectionEnabled;$o.defSigAge=[int]$m.AntivirusSignatureAge;$o.defTamper=[bool]$m.IsTamperProtected}else{$o.defPresent=$false}
$p=Get-MpPreference; if($p){$o.cfa=[int]$p.EnableControlledFolderAccess}
$o.fw=@(Get-NetFirewallProfile | ForEach-Object{@{Name=[string]$_.Name;Enabled=($_.Enabled -eq $true -or [string]$_.Enabled -eq 'True')}})
$b=Get-BitLockerVolume -MountPoint $env:SystemDrive; if($b){$o.bl=[int]$b.ProtectionStatus}
function rv($k,$n){try{$v=(Get-ItemProperty -Path $k -Name $n -ErrorAction Stop).$n; return [int]$v}catch{return $null}}
$sys='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$o.lua=rv $sys 'EnableLUA'; $o.consent=rv $sys 'ConsentPromptBehaviorAdmin'
$s=Get-SmbServerConfiguration; if($s){$o.smb1=[bool]$s.EnableSMB1Protocol}
$o.rdpDeny=rv 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
$o.rdpNla=rv 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
$g=Get-LocalUser | Where-Object{$_.SID.Value -like '*-501'}; if($g){$o.guest=[bool]$g.Enabled}
try{$o.secureBoot=[bool](Confirm-SecureBootUEFI -ErrorAction Stop)}catch{}
$o.reboot=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
$o.wdigest=rv 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
$o.llmnr=rv 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
$o.ppl=rv 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
$o.autorun=rv 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
$o.lmcompat=rv 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
$f=Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root; if($f){$o.psv2=[string]$f.State}
$o.edition=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
$o | ConvertTo-Json -Depth 4 -Compress`

const psFailedLogons = `
$since=(Get-Date).AddHours(-24)
$ev=Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$since} -MaxEvents 5000
$g=@{}
foreach($e in $ev){$x=[xml]$e.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'}
 $k=[string]$d.IpAddress+'|'+[string]$d.TargetUserName
 if(-not $g[$k]){$g[$k]=@{ip=[string]$d.IpAddress;user=[string]$d.TargetUserName;n=0;last=''}}
 $g[$k].n++; $t=$e.TimeCreated.ToString('yyyy-MM-dd HH:mm'); if($t -gt $g[$k].last){$g[$k].last=$t}}
ConvertTo-Json -InputObject @($g.Values) -Compress`



const psHardware = `
$o=@{disks=@()}
Get-PhysicalDisk | ForEach-Object{ $c=$_ | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
 $d=@{name=[string]$_.FriendlyName;media=[string]$_.MediaType;health=[string]$_.HealthStatus;size=[int64]$_.Size}
 if($c){ if($c.Wear -ne $null){$d.wear=[int]$c.Wear}; if($c.Temperature){$d.temp=[int]$c.Temperature}; if($c.ReadErrorsUncorrected -ne $null){$d.readErr=[int64]$c.ReadErrorsUncorrected} }
 $o.disks+=$d }
try{$s=Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData -ErrorAction Stop | Select-Object -First 1; $f=Get-CimInstance -Namespace root/wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop | Select-Object -First 1; $o.batDesign=[int64]$s.DesignedCapacity; $o.batFull=[int64]$f.FullChargedCapacity}catch{}
$v=Get-PSDrive ($env:SystemDrive.TrimEnd(':')); if($v){$o.sysFree=[int64]$v.Free; $o.sysSize=[int64]($v.Free+$v.Used)}
$o | ConvertTo-Json -Depth 4 -Compress`

const psEvents = `
$since=(Get-Date).AddDays(-7); $r=@()
function grp($k,$f,$x){ $e=@(Get-WinEvent -FilterHashtable $f -MaxEvents 500); if($e.Count){ $script:r+=@{k=$k;n=$e.Count;last=$e[0].TimeCreated.ToString('yyyy-MM-dd HH:mm');x=$x} } ; return $e }
$null=grp 'power41' @{LogName='System';ProviderName='Microsoft-Windows-Kernel-Power';Id=41;StartTime=$since} ''
$null=grp 'bugcheck' @{LogName='System';Id=1001;ProviderName='Microsoft-Windows-WER-SystemErrorReporting';StartTime=$since} ''
$null=grp 'disk' @{LogName='System';ProviderName='disk';Id=7,11,51,153;StartTime=$since} ''
$null=grp 'whea' @{LogName='System';ProviderName='Microsoft-Windows-WHEA-Logger';StartTime=$since} ''
$a=@(Get-WinEvent -FilterHashtable @{LogName='Application';Id=1000;StartTime=$since} -MaxEvents 500)
if($a.Count){ $apps=$a | ForEach-Object{ $_.Properties[0].Value } | Group-Object | Sort-Object Count -Descending | Select-Object -First 6 | ForEach-Object{ $_.Name+' ('+$_.Count+')' }; $r+=@{k='appcrash';n=$a.Count;last=$a[0].TimeCreated.ToString('yyyy-MM-dd HH:mm');x=('Programas: '+($apps -join ', '))} }
$s=@(Get-WinEvent -FilterHashtable @{LogName='System';Id=7031,7034;StartTime=$since} -MaxEvents 500)
if($s.Count){ $sv=$s | ForEach-Object{ $_.Properties[0].Value } | Group-Object | Sort-Object Count -Descending | Select-Object -First 6 | ForEach-Object{ $_.Name+' ('+$_.Count+')' }; $r+=@{k='svcfail';n=$s.Count;last=$s[0].TimeCreated.ToString('yyyy-MM-dd HH:mm');x=('Servicios: '+($sv -join ', '))} }
$d=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1116,1117;StartTime=$since} -MaxEvents 200)
if($d.Count){ $tn=$d | ForEach-Object{ ([xml]$_.ToXml()).Event.EventData.Data | Where-Object{$_.Name -eq 'Threat Name'} | ForEach-Object{$_.'#text'} } | Select-Object -Unique -First 5; $r+=@{k='defthreat';n=$d.Count;last=$d[0].TimeCreated.ToString('yyyy-MM-dd HH:mm');x=('Amenazas: '+($tn -join ', '))} }
$n=@(Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=$since} -MaxEvents 100)
if($n.Count){ $nm=$n | ForEach-Object{ $_.Properties[0].Value } | Select-Object -Unique -First 8; $r+=@{k='newsvc';n=$n.Count;last=$n[0].TimeCreated.ToString('yyyy-MM-dd HH:mm');x=('Servicios: '+($nm -join ', '))} }
$null=grp 'logclear' @{LogName='Security';Id=1102;StartTime=$since} ''
ConvertTo-Json -InputObject @($r) -Compress`

const psPersist = `
$r=@()
foreach($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'){
 $p=Get-ItemProperty $k; if($p){ $p.PSObject.Properties | Where-Object{$_.Name -notlike 'PS*'} | ForEach-Object{ $r+=@{k='run';n=$_.Name;c=[string]$_.Value} } } }
Get-ChildItem 'Registry::HKEY_USERS' | Where-Object{$_.Name -match 'S-1-5-21-[\d-]+$'} | ForEach-Object{ $p=Get-ItemProperty ($_.PSPath+'\Software\Microsoft\Windows\CurrentVersion\Run'); if($p){ $p.PSObject.Properties | Where-Object{$_.Name -notlike 'PS*'} | ForEach-Object{ $r+=@{k='run';n=$_.Name;c=[string]$_.Value} } } }
Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -File -Force | ForEach-Object{ $r+=@{k='run';n=$_.Name;c=$_.FullName} }
Get-ScheduledTask | Where-Object{ $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object{ $a=($_.Actions | ForEach-Object{ ([string]$_.Execute+' '+[string]$_.Arguments).Trim() }) -join ' ; '; $r+=@{k='task';n=($_.TaskPath+$_.TaskName);c=$a} }
Get-CimInstance Win32_Service | Where-Object{ $_.StartMode -eq 'Auto' } | ForEach-Object{ $r+=@{k='service';n=[string]$_.Name;c=[string]$_.PathName} }
$adm=Get-LocalGroup | Where-Object{ $_.SID.Value -eq 'S-1-5-32-544' }; if($adm){ Get-LocalGroupMember -Group $adm | ForEach-Object{ $r+=@{k='admin';n=[string]$_.Name;c=[string]$_.SID.Value} } }
ConvertTo-Json -InputObject @($r) -Compress`

const psWU = `
$s=New-Object -ComObject Microsoft.Update.Session; $q=$s.CreateUpdateSearcher()
$res=$q.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
$r=@(); foreach($u in $res.Updates){ $r+=@{id=$u.Identity.UpdateID;t=$u.Title;kb=(@($u.KBArticleIDs) -join ',');sev=[string]$u.MsrcSeverity;reboot=[bool]$u.RebootRequired;cat=(@($u.Categories|ForEach-Object{$_.Name}) -join ', ')} }
ConvertTo-Json -InputObject @($r) -Compress`

// ---------- registro de analizadores ----------

var kevCache struct {
	sync.Mutex
	l    []KEVEntry
	when time.Time
}

func getKEV() []KEVEntry {
	kevCache.Lock()
	defer kevCache.Unlock()
	if time.Since(kevCache.when) < 6*time.Hour && kevCache.l != nil {
		return kevCache.l
	}
	l, err := FetchKEV()
	if err == nil {
		kevCache.l, kevCache.when = l, time.Now()
	}
	return kevCache.l
}

func psJSON[T any](script string, timeout time.Duration) ([]T, error) {
	out, err := runPS(script, timeout)
	if err != nil {
		return nil, err
	}
	return PSList[T](out), nil
}

func psObj[T any](script string, timeout time.Duration) (T, error) {
	var v T
	out, err := runPS(script, timeout)
	if err != nil {
		return v, err
	}
	out = strings.TrimSpace(strings.TrimPrefix(out, "\ufeff"))
	if out == "" {
		return v, fmt.Errorf("sin respuesta de Windows")
	}
	err = json.Unmarshal([]byte(out), &v)
	return v, err
}

func wingetPath() string {
	if p, err := exec.LookPath("winget.exe"); err == nil {
		return p
	}
	// Con otra cuenta (.adm) o como SYSTEM winget no está en el PATH: se busca el paquete instalado
	matches, _ := filepath.Glob(filepath.Join(os.Getenv("ProgramFiles"), "WindowsApps", "Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe", "winget.exe"))
	if len(matches) > 0 {
		return matches[len(matches)-1]
	}
	return ""
}

func registerScanners(e *Engine) {
	e.AddScanner(Scanner{Name: "seguridad de Windows", Cmd: "Get-MpComputerStatus · Get-NetFirewallProfile · Get-BitLockerVolume · Get-SmbServerConfiguration …", Cats: []string{"Seguridad", "Endurecimiento"}, Order: 1, Run: func(e *Engine) ([]*Item, error) {
		s, err := psObj[SecInfo](psSecurity, 3*time.Minute)
		if err != nil {
			return nil, err
		}
		return BuildSecurity(s), nil
	}})
	e.AddScanner(Scanner{Name: "puertos", Cmd: "Tabla de conexiones de Windows (GetExtendedTcpTable / GetExtendedUdpTable)", Cats: []string{"Red"}, Order: 2, Run: func(e *Engine) ([]*Item, error) {
		procs := map[int]nProc{}
		for _, p := range ProcList(false) {
			procs[p.PID] = p
		}
		var l []Listener
		for _, c := range NetConns(true) {
			if c.Proto == "TCP" && c.State != "Listen" {
				continue
			}
			p := procs[c.PID]
			l = append(l, Listener{Addr: c.LAddr, Port: c.LPort, Proto: c.Proto, Proc: strings.TrimSuffix(p.Name, ".exe"), Path: p.Path, PID: c.PID})
		}
		return BuildListeners(l), nil
	}})
	e.AddScanner(Scanner{Name: "intrusiones", Cmd: "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} (últimas 24 h)", Cats: []string{"Intrusiones"}, Order: 3, Run: func(e *Engine) ([]*Item, error) {
		l, err := psJSON[FailedLogon](psFailedLogons, 2*time.Minute)
		if err != nil {
			return nil, err
		}
		return BuildIntrusions(l), nil
	}})
	e.AddScanner(Scanner{Name: "hardware", Cmd: "Get-PhysicalDisk | Get-StorageReliabilityCounter · BatteryFullChargedCapacity", Cats: []string{"Hardware"}, Order: 4, Run: func(e *Engine) ([]*Item, error) {
		h, err := psObj[HWInfo](psHardware, 2*time.Minute)
		if err != nil {
			return nil, err
		}
		return BuildHardware(h), nil
	}})
	e.AddScanner(Scanner{Name: "eventos", Cmd: "Get-WinEvent System/Application/Defender (últimos 7 días)", Cats: []string{"Eventos"}, Order: 5, Run: func(e *Engine) ([]*Item, error) {
		l, err := psJSON[EvGroup](psEvents, 3*time.Minute)
		if err != nil {
			return nil, err
		}
		return BuildEvents(l), nil
	}})
	e.AddScanner(Scanner{Name: "cambios", Cmd: "Get-ScheduledTask · Win32_Service · Run · Get-LocalGroupMember Administradores", Cats: []string{"Cambios"}, Order: 6, Run: func(e *Engine) ([]*Item, error) {
		l, err := psJSON[PersistEntry](psPersist, 3*time.Minute)
		if err != nil {
			return nil, err
		}
		var base map[string]bool
		bp := e.St.Path("base-persistencia.json")
		if readJSON(bp, &base) != nil {
			base = nil
		}
		items := BuildChanges(l, base)
		if base == nil {
			base = map[string]bool{}
			for _, p := range l {
				base[persistKey(p)] = true
			}
			_ = writeJSON(bp, base)
			e.Log("info", "Cambios: guardada la foto inicial de programas de inicio, tareas, servicios y administradores (%d).", len(base))
		}
		return items, nil
	}})
	e.AddScanner(Scanner{Name: "limpieza", Cmd: "Midiendo carpetas temporales, cachés, papeleras y descargas de Windows Update", Cats: []string{"Limpieza"}, Order: 7, Run: func(e *Engine) ([]*Item, error) {
		return BuildJunk(MeasureJunk()), nil
	}})
	e.AddScanner(Scanner{Name: "programas", Cmd: "winget upgrade --include-unknown --accept-source-agreements", Cats: []string{"Programas"}, Order: 8, Slow: true, Run: func(e *Engine) ([]*Item, error) {
		wg := wingetPath()
		if wg == "" {
			return []*Item{{ID: "w:nowinget", Category: "Programas", Name: "Instalador de aplicaciones (winget)", Status: "Revisar", Action: "open", Arg: "ms-windows-store://pdp/?productid=9NBLGGH4NNS1",
				Detail: "No se encuentra winget, que es lo que se usa para actualizar los programas. Instala o actualiza «Instalador de aplicaciones» desde Microsoft Store."}}, nil
		}
		out, _, err := runExe(6*time.Minute, wg, "upgrade", "--include-unknown", "--accept-source-agreements", "--disable-interactivity")
		if err != nil {
			return nil, err
		}
		pk := ParseWingetTable(out)
		return BuildPrograms(pk, getKEV()), nil
	}})
	e.AddScanner(Scanner{Name: "Windows Update", Cmd: "Microsoft.Update.Session → Search(\"IsInstalled=0 and IsHidden=0\")", Cats: []string{"Windows"}, Order: 9, Slow: true, Run: func(e *Engine) ([]*Item, error) {
		wantWU := true
		e.St.WithCfg(func(c *Config) { wantWU = c.Settings.WU })
		if !wantWU {
			return nil, nil
		}
		type wu struct {
			ID     string `json:"id"`
			T      string `json:"t"`
			KB     string `json:"kb"`
			Sev    string `json:"sev"`
			Reboot bool   `json:"reboot"`
			Cat    string `json:"cat"`
		}
		l, err := psJSON[wu](psWU, 8*time.Minute)
		if err != nil {
			return nil, err
		}
		var items []*Item
		for _, u := range l {
			st := "Actualizar"
			if u.Sev == "Critical" || u.Sev == "Important" {
				st = "Vulnerable"
			}
			it := &Item{ID: "wu:" + u.ID, Category: "Windows", Name: u.T, Status: st, Action: "winupdate", Arg: u.ID, Reboot: u.Reboot, Available: ternary(u.KB != "", "KB"+u.KB, "-"),
				Detail: "Actualización de Windows pendiente" + ternary(u.Cat != "", " ("+u.Cat+")", "") + "." + ternary(u.Sev != "", " Gravedad según Microsoft: "+sevES(u.Sev)+".", "") + ternary(u.Reboot, " Necesita reiniciar.", "")}
			items = append(items, it)
		}
		return items, nil
	}})
}

func sevES(s string) string {
	return map[string]string{"Critical": "crítica", "Important": "importante", "Moderate": "moderada", "Low": "baja"}[s]
}
