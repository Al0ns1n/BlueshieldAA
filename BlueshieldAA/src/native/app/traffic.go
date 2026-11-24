package main

import (
	"net"
	"strconv"
	"strings"
)

type Conn struct {
	Proc   string `json:"proc"`
	Path   string `json:"path"`
	PID    int    `json:"pid"`
	Proto  string `json:"proto"`
	Local  string `json:"local"`
	Remote string `json:"remote"`
	Host   string `json:"host"`
	Svc    string `json:"svc"`
	State  string `json:"state"`
	Scope  string `json:"scope"`
	Risk   string `json:"risk"`
	Note   string `json:"note"`
	Cat    string `json:"cat"`    // tipo de programa: Navegador, Sistema, Comunicación…
	SvcCat string `json:"svcCat"` // tipo de tráfico: Web segura, DNS, Correo, Remoto…
	Org    string `json:"org"`    // dueño de la IP (Google, Microsoft, Cloudflare…)
	CC     string `json:"cc"`     // país de la IP (ES, US, IE…)
	Dir    string `json:"dir"`    // "sale" (el equipo se conecta) o "entra" (alguien se conecta al equipo)
	IPv6   bool   `json:"ipv6"`
	Since  int64  `json:"since"` // cuándo la vimos por primera vez (ms)
}

type TPoint struct {
	T   int64   `json:"t"`
	In  float64 `json:"in"`
	Out float64 `json:"out"`
}

type TrafficOut struct {
	Conns    []Conn   `json:"conns"`
	Internet int      `json:"internet"`
	Procs    int      `json:"procs"`
	InBps    float64  `json:"inBps"`
	OutBps   float64  `json:"outBps"`
	Hist     []TPoint `json:"hist"`
	PeakIn   float64  `json:"peakIn"`
	PeakOut  float64  `json:"peakOut"`
	Listen   int      `json:"listen"`
}

var svcNames = map[int]string{20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTP seguro", 587: "SMTP", 636: "LDAPS", 993: "IMAP seguro", 995: "POP3 seguro", 1433: "SQL Server", 1194: "OpenVPN", 3306: "MySQL", 3389: "Escritorio remoto", 5222: "XMPP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM", 8080: "HTTP alternativo", 8443: "HTTPS alternativo", 9001: "Tor", 9050: "Tor", 4444: "Metasploit (típico)", 6667: "IRC"}

var sysBins = map[string]bool{"svchost": true, "lsass": true, "csrss": true, "winlogon": true, "services": true, "smss": true, "explorer": true, "rundll32": true, "dllhost": true, "taskhostw": true, "spoolsv": true, "wininit": true, "conhost": true, "searchindexer": true}

func scopeOf(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	if p.IsLoopback() || p.IsUnspecified() {
		return "Local"
	}
	if p.IsPrivate() || p.IsLinkLocalUnicast() || strings.HasPrefix(ip, "100.64.") {
		return "LAN"
	}
	return "Internet"
}

// ClassifyConn rellena servicio, ámbito y riesgo de una conexión.
func ClassifyConn(c *Conn, rip string, rport int) {
	c.Scope = scopeOf(rip)
	c.Svc = svcNames[rport]
	if c.Svc == "" && rport > 0 {
		c.Svc = "puerto " + strconv.Itoa(rport)
	}
	lp := strings.ToLower(c.Path)
	name := strings.ToLower(strings.TrimSuffix(c.Proc, ".exe"))
	switch {
	case lp != "" && hasAny(lp, `\appdata\local\temp\`, `\windows\temp\`, `\users\public\`, `\$recycle.bin\`, `\programdata\temp`) && c.Scope == "Internet":
		c.Risk, c.Note = "Alerta", "Un programa que se ejecuta desde una carpeta temporal está conectado a Internet. Es muy típico del malware."
	case sysBins[name] && lp != "" && !strings.Contains(lp, `\windows\system32\`) && !strings.Contains(lp, `\windows\syswow64\`) && !strings.HasSuffix(lp, `\windows\explorer.exe`):
		c.Risk, c.Note = "Alerta", "Tiene el nombre de un componente de Windows pero no está en su carpeta: puede ser malware disfrazado."
	case c.Scope == "Internet" && (rport == 4444 || rport == 6667 || rport == 9001 || rport == 9050):
		c.Risk, c.Note = "Revisar", "Conecta a un puerto que suelen usar herramientas de control remoto de atacantes o Tor."
	case c.Scope == "Internet" && (rport == 3389 || rport == 445 || rport == 5985 || rport == 5986 || rport == 23 || rport == 135):
		c.Risk, c.Note = "Revisar", "Tráfico de administración o de carpetas compartidas saliendo a Internet. No es habitual en un equipo de oficina."
	case lp != "" && strings.Contains(lp, `\downloads\`) && c.Scope == "Internet":
		c.Risk, c.Note = "Revisar", "Un programa ejecutado directamente desde Descargas está conectado a Internet."
	}
}

func SplitHostPort(s string) (string, int) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return s, 0
	}
	n, _ := strconv.Atoi(p)
	return h, n
}

// ---------- categorías ----------

// appCats: tipo de programa por nombre del ejecutable (sin .exe, en minúsculas).
var appCats = []struct {
	cat   string
	names []string
}{
	{"Navegador", []string{"chrome", "msedge", "firefox", "brave", "opera", "opera_gx", "vivaldi", "iexplore", "arc", "msedgewebview2", "librewolf", "waterfox", "tor", "thorium"}},
	{"Comunicación", []string{"teams", "ms-teams", "msteams", "discord", "slack", "zoom", "skype", "whatsapp", "telegram", "signal", "webex", "ciscocollabhost", "outlook", "olk", "thunderbird", "hxoutlook", "hxtsr", "mailspring", "anydesk", "teamviewer", "rustdesk"}},
	{"Nube y sincronización", []string{"onedrive", "filecoauth", "dropbox", "googledrivefs", "icloudservices", "icloud", "box", "megasync", "nextcloud", "pcloud", "synologydrive", "officeclicktorun", "sdxhelper"}},
	{"Juegos", []string{"steam", "steamwebhelper", "epicgameslauncher", "epicwebhelper", "riotclientservices", "riotclientux", "leagueclient", "league of legends", "valorant", "battle.net", "agent", "eadesktop", "eabackgroundservice", "ubisoftconnect", "upc", "gog galaxy", "galaxyclient", "xboxapp", "gamingservices", "minecraft", "javaw", "robloxplayerbeta"}},
	{"Música y vídeo", []string{"spotify", "vlc", "netflix", "obs64", "obs32", "itunes", "applemusic", "tidal", "deezer", "plex", "kodi", "twitch", "prime video"}},
	{"Seguridad", []string{"msmpeng", "mpdefendercoreservice", "nissrv", "smartscreen", "securityhealthservice", "mbamservice", "ekrn", "egui", "avastsvc", "avgsvc", "bdservicehost", "mcshield", "sentinelagent", "csfalconservice", "blueshieldaa"}},
	{"Desarrollo", []string{"code", "devenv", "node", "python", "pythonw", "java", "git", "git-remote-https", "ssh", "docker", "com.docker.backend", "wsl", "wslhost", "idea64", "pycharm64", "rider64", "cursor", "postman", "winget", "npm", "dotnet", "claude"}},
	{"Actualizaciones", []string{"wuauclt", "usoclient", "musnotification", "tiworker", "trustedinstaller", "microsoftedgeupdate", "googleupdate", "updater", "update", "softwareupdate", "adobearm", "msiexec", "setup", "installer", "appinstaller", "winstore.app", "wsappx"}},
	{"Sistema Windows", []string{"svchost", "system", "lsass", "services", "wininit", "csrss", "searchhost", "searchapp", "searchui", "searchindexer", "explorer", "runtimebroker", "backgroundtaskhost", "taskhostw", "smartscreen", "startmenuexperiencehost", "widgets", "widgetservice", "phoneexperiencehost", "yourphone", "crossdeviceservice", "lockapp", "spoolsv", "dashost", "wlanext", "officesvcmgr", "compattelrunner", "sihost", "ctfmon"}},
}

// AppCategory clasifica el programa que hace la conexión.
func AppCategory(proc, path string) string {
	n := strings.ToLower(strings.TrimSuffix(strings.ToLower(proc), ".exe"))
	for _, c := range appCats {
		for _, x := range c.names {
			if n == x {
				return c.cat
			}
		}
	}
	lp := strings.ToLower(path)
	switch {
	case strings.Contains(lp, `\windows\system32\`) || strings.Contains(lp, `\windows\syswow64\`):
		return "Sistema Windows"
	case strings.Contains(lp, `\steamapps\`) || strings.Contains(lp, `\epic games\`) || strings.Contains(lp, `\riot games\`):
		return "Juegos"
	case strings.Contains(lp, `\windowsapps\`):
		return "Apps de la Tienda"
	}
	return "Otros programas"
}

// SvcCategory agrupa los servicios por lo que hacen.
func SvcCategory(port int) string {
	switch port {
	case 443, 8443:
		return "Web segura"
	case 80, 8080, 8000, 8888:
		return "Web sin cifrar"
	case 53, 853:
		return "DNS"
	case 25, 465, 587, 110, 995, 143, 993:
		return "Correo"
	case 22, 23, 3389, 5900, 5985, 5986:
		return "Acceso remoto"
	case 445, 139, 135, 137, 138, 2049:
		return "Archivos compartidos"
	case 123:
		return "Hora"
	case 1194, 1701, 1723, 500, 4500, 51820:
		return "VPN"
	case 3478, 3479, 3480, 3481, 19302, 50000:
		return "Llamadas y vídeo"
	case 1433, 3306, 5432, 27017, 6379:
		return "Bases de datos"
	case 4444, 6667, 9001, 9050:
		return "Sospechoso"
	case 0:
		return "Otro"
	}
	if port >= 27000 && port <= 27100 {
		return "Juegos"
	}
	return "Otro"
}

// ---------- dueño y país de una IP (Team Cymru por DNS: gratis y sin clave) ----------

// CymruQuery devuelve el nombre a consultar (TXT) para una IPv4: 8.8.8.8 → 8.8.8.8.origin.asn.cymru.com
func CymruQuery(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	if v4 := p.To4(); v4 != nil {
		return strconv.Itoa(int(v4[3])) + "." + strconv.Itoa(int(v4[2])) + "." + strconv.Itoa(int(v4[1])) + "." + strconv.Itoa(int(v4[0])) + ".origin.asn.cymru.com"
	}
	const hx = "0123456789abcdef"
	b := make([]byte, 0, 64)
	for i := 15; i >= 0; i-- {
		b = append(b, hx[p[i]&0xf], '.', hx[p[i]>>4], '.')
	}
	return string(b) + "origin6.asn.cymru.com"
}

// ParseCymruOrigin: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01" → ASN y país.
func ParseCymruOrigin(txt string) (asn, cc string) {
	f := strings.Split(txt, "|")
	if len(f) < 3 {
		return "", ""
	}
	asn = strings.Fields(strings.TrimSpace(f[0]) + " ")[0]
	return asn, strings.TrimSpace(f[2])
}

// ParseCymruAS: "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US" → "Google LLC".
func ParseCymruAS(txt string) string {
	f := strings.Split(txt, "|")
	if len(f) < 5 {
		return ""
	}
	n := strings.TrimSpace(f[4])
	if i := strings.Index(n, " - "); i >= 0 {
		n = n[i+3:]
	}
	if i := strings.LastIndex(n, ","); i > 0 && len(n)-i <= 4 {
		n = n[:i]
	}
	return prettyOrg(strings.TrimSpace(n))
}

// prettyOrg acorta los nombres conocidos para que se entiendan de un vistazo.
func prettyOrg(n string) string {
	l := strings.ToLower(n)
	for _, k := range [][2]string{{"google", "Google"}, {"microsoft", "Microsoft"}, {"amazon", "Amazon (AWS)"}, {"cloudflare", "Cloudflare"}, {"akamai", "Akamai"}, {"facebook", "Meta"}, {"meta platforms", "Meta"},
		{"apple", "Apple"}, {"fastly", "Fastly"}, {"telefonica", "Telefónica"}, {"vodafone", "Vodafone"}, {"orange", "Orange"}, {"digitalocean", "DigitalOcean"}, {"ovh", "OVH"}, {"hetzner", "Hetzner"},
		{"valve", "Valve (Steam)"}, {"riot", "Riot Games"}, {"spotify", "Spotify"}, {"discord", "Discord"}, {"zoom", "Zoom"}, {"oracle", "Oracle"}, {"edgecast", "Edgio"}, {"twitter", "X (Twitter)"}, {"netflix", "Netflix"}} {
		if strings.Contains(l, k[0]) {
			return k[1]
		}
	}
	return n
}
