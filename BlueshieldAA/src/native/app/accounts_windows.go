//go:build windows

package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// MyAccounts: cuentas encontradas en este equipo para el usuario que está delante de la pantalla.
func MyAccounts() map[string]any {
	home := desktopUserHome()
	sid := desktopUserSID()
	var s AccountSet
	local := filepath.Join(home, "AppData", "Local")
	roaming := filepath.Join(home, "AppData", "Roaming")
	for _, b := range []struct{ path, name, hint string }{
		{`Google\Chrome\User Data\Local State`, "Google Chrome", "google"},
		{`Microsoft\Edge\User Data\Local State`, "Microsoft Edge", "aad"},
		{`BraveSoftware\Brave-Browser\User Data\Local State`, "Brave", "google"},
		{`Vivaldi\User Data\Local State`, "Vivaldi", ""},
	} {
		if raw, err := os.ReadFile(filepath.Join(local, b.path)); err == nil {
			for _, c := range ChromiumAccounts(raw) {
				s.Add(c[0], c[1], b.name, b.hint)
			}
		}
	}
	if m, _ := filepath.Glob(filepath.Join(roaming, `Mozilla\Firefox\Profiles\*\signedInUser.json`)); len(m) > 0 {
		for _, f := range m {
			if raw, err := os.ReadFile(f); err == nil {
				s.Add(FirefoxAccount(raw), "", "Firefox", "")
			}
		}
	}
	if m, _ := filepath.Glob(filepath.Join(roaming, `Thunderbird\Profiles\*\prefs.js`)); len(m) > 0 {
		for _, f := range m {
			if raw, err := os.ReadFile(f); err == nil {
				for _, e := range ThunderbirdAccounts(raw) {
					s.Add(e, "", "Thunderbird", "")
				}
			}
		}
	}
	root, base := registry.USERS, sid+`\`
	if sid == "" {
		root, base = registry.CURRENT_USER, ""
	}
	// Office y Outlook
	if k, err := registry.OpenKey(root, base+`Software\Microsoft\Office\16.0\Common\Identity\Identities`, registry.ENUMERATE_SUB_KEYS); err == nil {
		subs, _ := k.ReadSubKeyNames(0)
		for _, n := range subs {
			if sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE); err == nil {
				mail, _, _ := sk.GetStringValue("EmailAddress")
				prov, _, _ := sk.GetStringValue("ProviderId")
				name, _, _ := sk.GetStringValue("FriendlyName")
				sk.Close()
				s.Add(mail, name, "Office / Outlook", ternary(strings.EqualFold(prov, "LiveId"), "msa", "aad"))
			}
		}
		k.Close()
	}
	// Cuenta Microsoft con la que se entra en Windows (o añadida en «Correo y cuentas»)
	if k, err := registry.OpenKey(root, base+`Software\Microsoft\IdentityCRL\UserExtendedProperties`, registry.ENUMERATE_SUB_KEYS); err == nil {
		subs, _ := k.ReadSubKeyNames(0)
		for _, n := range subs {
			s.Add(n, "", "Windows", "msa")
		}
		k.Close()
	}
	return map[string]any{"accounts": s.List(), "user": filepath.Base(home)}
}

const psLogons = `
$xp = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= 1209600000]] and EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='7' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11']]"
$r=@()
Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents 400 -ErrorAction SilentlyContinue | ForEach-Object {
 $x=[xml]$_.ToXml(); $d=@{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' }
 $u=[string]$d['TargetUserName']; if($u -match '^(DWM-|UMFD-|SYSTEM$|ANONYMOUS)' -or $u.EndsWith('$')){ return }
 $r+=@{t=$_.TimeCreated.ToString('o');u=([string]$d['TargetDomainName']+'\'+$u);ty=[int]$d['LogonType'];ip=[string]$d['IpAddress'];ws=[string]$d['WorkstationName']}
}
$f=@(Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 1209600000]]]" -MaxEvents 2000 -ErrorAction SilentlyContinue)
@{ok=$r;failed=$f.Count;failedIPs=@($f | ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object Name -eq 'IpAddress' | ForEach-Object { $_.'#text' } } | Where-Object { $_ -and $_ -ne '-' } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { @{ip=$_.Name;n=$_.Count} })} | ConvertTo-Json -Depth 4 -Compress`

type logonRow struct {
	T    string `json:"t"`
	U    string `json:"u"`
	Ty   int    `json:"ty"`
	IP   string `json:"ip"`
	WS   string `json:"ws"`
	Kind string `json:"kind"`
	CC   string `json:"cc"`
	Org  string `json:"org"`
	Pub  bool   `json:"pub"`
}

// Logons: inicios de sesión en ESTE equipo (registro de Seguridad de Windows, últimos 14 días).
func Logons() map[string]any {
	type res struct {
		OK        []logonRow `json:"ok"`
		Failed    int        `json:"failed"`
		FailedIPs []struct {
			IP string `json:"ip"`
			N  int    `json:"n"`
		} `json:"failedIPs"`
	}
	r, err := psObj[*res](psLogons, 90*time.Second)
	if err != nil || r == nil {
		return map[string]any{"error": "No se ha podido leer el registro de seguridad de Windows (hace falta abrir BlueShieldAA como administrador)."}
	}
	kinds := map[int]string{2: "En el equipo", 7: "Desbloqueo", 10: "Escritorio remoto", 11: "Sin conexión (credenciales guardadas)"}
	// se juntan los repetidos (mismo usuario, tipo e IP en la misma hora)
	seen := map[string]bool{}
	out := []logonRow{}
	for _, x := range r.OK {
		x.Kind = kinds[x.Ty]
		if x.IP == "-" || x.IP == "::1" || x.IP == "127.0.0.1" {
			x.IP = ""
		}
		k := x.U + "|" + itoa(x.Ty) + "|" + x.IP + "|" + cutS(x.T, 13)
		if seen[k] {
			continue
		}
		seen[k] = true
		if x.IP != "" && scopeOf(x.IP) == "Internet" {
			x.Pub = true
			x.Org, x.CC = ipOwnerWait(x.IP)
		}
		out = append(out, x)
		if len(out) >= 60 {
			break
		}
	}
	type fip struct {
		IP  string `json:"ip"`
		N   int    `json:"n"`
		CC  string `json:"cc"`
		Org string `json:"org"`
	}
	fl := []fip{}
	for _, f := range r.FailedIPs {
		x := fip{IP: f.IP, N: f.N}
		if scopeOf(f.IP) == "Internet" {
			x.Org, x.CC = ipOwnerWait(f.IP)
		}
		fl = append(fl, x)
	}
	return map[string]any{"logons": out, "failed": r.Failed, "failedIPs": fl}
}

func cutS(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ipOwnerWait: como ipOwner pero esperando la respuesta (hasta 3 s).
func ipOwnerWait(ip string) (string, string) {
	if net.ParseIP(ip) == nil {
		return "", ""
	}
	for i := 0; i < 15; i++ {
		org, cc := ipOwner(ip)
		if org != "" || cc != "" {
			return org, cc
		}
		time.Sleep(200 * time.Millisecond)
	}
	return "", ""
}
