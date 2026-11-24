package main

// Construcción de elementos a partir de lo que se lee de Windows. Portable para poder probarlo.

import (
	"fmt"
	"sort"
	"strings"
)

// ---------- Ajustes de seguridad y endurecimiento ----------

type SecInfo struct {
	AV []struct {
		Name  string `json:"name"`
		State int    `json:"state"`
	} `json:"av"`
	DefPresent bool  `json:"defPresent"`
	DefEnabled bool  `json:"defEnabled"`
	DefRT      bool  `json:"defRT"`
	DefSigAge  int   `json:"defSigAge"`
	DefTamper  *bool `json:"defTamper"`
	CFA        *int  `json:"cfa"`
	FW         []struct {
		Name    string `json:"Name"`
		Enabled bool   `json:"Enabled"`
	} `json:"fw"`
	BL         *int   `json:"bl"`
	LUA        *int   `json:"lua"`
	Consent    *int   `json:"consent"`
	SMB1       *bool  `json:"smb1"`
	RDPDeny    *int   `json:"rdpDeny"`
	RDPNLA     *int   `json:"rdpNla"`
	Guest      *bool  `json:"guest"`
	SecureBoot *bool  `json:"secureBoot"`
	Reboot     bool   `json:"reboot"`
	WDigest    *int   `json:"wdigest"`
	LLMNR      *int   `json:"llmnr"`
	PPL        *int   `json:"ppl"`
	AutoRun    *int   `json:"autorun"`
	PSv2       string `json:"psv2"`
	LMCompat   *int   `json:"lmcompat"`
	Edition    string `json:"edition"`
}

func iv(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}

func BuildSecurity(s SecInfo) []*Item {
	var l []*Item
	add := func(it *Item) { it.Category = ternary(it.Category == "", "Seguridad", it.Category); l = append(l, it) }

	// Antivirus: productos de terceros activos (bit 0x1000 de productState = activado)
	third := []string{}
	for _, a := range s.AV {
		if !strings.Contains(strings.ToLower(a.Name), "defender") && a.State&0x1000 != 0 {
			third = append(third, a.Name)
		}
	}
	switch {
	case s.DefPresent && s.DefEnabled && s.DefRT:
		add(&Item{ID: "sec:av", Name: "Antivirus (Microsoft Defender)", Status: "Al día", Current: "Activado", Detail: "La protección en tiempo real está activada."})
	case len(third) > 0:
		add(&Item{ID: "sec:av", Name: "Antivirus (" + third[0] + ")", Status: "Al día", Current: "Activado", Detail: "Windows indica que " + strings.Join(third, ", ") + " protege el equipo."})
	default:
		add(&Item{ID: "sec:av", Name: "Antivirus en tiempo real", Status: "Vulnerable", Action: "open", Arg: "windowsdefender://threatsettings", Current: "Desactivado",
			Detail: "No hay ningún antivirus vigilando en tiempo real. Cualquier archivo malicioso que llegue se podría ejecutar sin que nadie lo detenga. Al pulsar Abrir se abre Seguridad de Windows: activa «Protección en tiempo real»."})
	}
	if s.DefPresent && s.DefEnabled && len(third) == 0 {
		if s.DefSigAge > 3 {
			add(&Item{ID: "sec:sig", Name: "Firmas de Microsoft Defender", Status: "Actualizar", Action: "defsig", Current: fmt.Sprintf("hace %d días", s.DefSigAge),
				Detail: "Las firmas del antivirus tienen varios días. Sin ellas no reconoce el malware más reciente."})
		} else {
			add(&Item{ID: "sec:sig", Name: "Firmas de Microsoft Defender", Status: "Al día", Current: ternary(s.DefSigAge <= 0, "hoy", fmt.Sprintf("hace %d días", s.DefSigAge)), Detail: "Las firmas del antivirus están recientes."})
		}
		if s.DefTamper != nil && !*s.DefTamper {
			add(&Item{ID: "sec:tamper", Name: "Protección contra alteraciones", Status: "Revisar", Action: "open", Arg: "windowsdefender://threatsettings", Current: "Desactivada",
				Detail: "Impide que un malware apague Defender. Solo se puede activar a mano: Seguridad de Windows → Protección antivirus → Administrar la configuración."})
		}
		if s.CFA != nil && *s.CFA == 0 {
			add(&Item{ID: "sec:cfa", Name: "Acceso controlado a carpetas", Status: "Info", Action: "cfa", Current: "Desactivado",
				Detail: "Bloquea que programas desconocidos cambien tus documentos (protección contra ransomware de Windows). Algunos programas legítimos pueden necesitar que los permitas después."})
		}
	}
	// Firewall
	for _, f := range s.FW {
		n := map[string]string{"Domain": "dominio", "Private": "privada", "Public": "pública"}[f.Name]
		if n == "" {
			n = f.Name
		}
		if f.Enabled {
			add(&Item{ID: "sec:fw:" + f.Name, Name: "Firewall (red " + n + ")", Status: "Al día", Current: "Activado", Detail: "El firewall de Windows filtra las conexiones entrantes en este tipo de red."})
		} else {
			add(&Item{ID: "sec:fw:" + f.Name, Name: "Firewall (red " + n + ")", Status: "Vulnerable", Action: "firewall", Arg: f.Name, Current: "Desactivado",
				Detail: "El firewall está apagado en las redes de tipo " + n + ": cualquier equipo de esa red puede llegar a los servicios abiertos de este."})
		}
	}
	// BitLocker
	if s.BL != nil {
		if *s.BL == 1 {
			add(&Item{ID: "sec:bl", Name: "Cifrado del disco (BitLocker)", Status: "Al día", Current: "Activado", Detail: "Si roban o pierden el equipo, nadie puede leer el disco sin la clave."})
		} else {
			add(&Item{ID: "sec:bl", Name: "Cifrado del disco (BitLocker)", Status: "Revisar", Action: "open", Arg: "ms-settings:deviceencryption", Current: "Desactivado",
				Detail: "El disco del sistema no está cifrado: si se pierde o roban el portátil, se puede leer todo su contenido. Actívalo y guarda la clave de recuperación (en Entra ID o en lugar seguro)."})
		}
	}
	// UAC
	if iv(s.LUA, 1) == 0 {
		add(&Item{ID: "sec:uac", Name: "Control de cuentas de usuario (UAC)", Status: "Vulnerable", Action: "uac", Current: "Desactivado", Reboot: true,
			Detail: "Con el UAC apagado, cualquier programa que se ejecute con una cuenta de administrador tiene todos los permisos sin preguntar."})
	} else if iv(s.Consent, 5) == 0 {
		add(&Item{ID: "sec:uac", Name: "Control de cuentas de usuario (UAC)", Status: "Revisar", Action: "uac", Current: "Sin avisos",
			Detail: "El UAC no pide confirmación a los administradores: los programas se elevan solos."})
	} else {
		add(&Item{ID: "sec:uac", Name: "Control de cuentas de usuario (UAC)", Status: "Al día", Current: "Activado", Detail: "Windows pide permiso antes de que un programa haga cambios de administrador."})
	}
	if s.SMB1 != nil && *s.SMB1 {
		add(&Item{ID: "sec:smb1", Name: "Protocolo SMBv1", Status: "Vulnerable", Action: "smb1", Current: "Activado", Reboot: true,
			Detail: "Versión antigua de compartir carpetas, la que usaron WannaCry y NotPetya para propagarse. Ningún equipo moderno la necesita."})
	}
	if iv(s.RDPDeny, 1) == 0 {
		if iv(s.RDPNLA, 1) == 0 {
			add(&Item{ID: "sec:rdp", Name: "Escritorio remoto sin autenticación previa (NLA)", Status: "Vulnerable", Action: "rdpnla", Current: "Activado sin NLA",
				Detail: "Cualquiera que llegue al puerto 3389 ve la pantalla de inicio de sesión de Windows y puede probar contraseñas o explotar fallos de RDP sin autenticarse."})
		} else {
			add(&Item{ID: "sec:rdp", Name: "Escritorio remoto activado", Status: "Info", Action: "rdpoff", Current: "Activado (con NLA)",
				Detail: "Se puede entrar en remoto a este equipo. Si no lo usas, desactívalo; si lo usas, que solo sea a través de la VPN."})
		}
	}
	if s.Guest != nil && *s.Guest {
		add(&Item{ID: "sec:guest", Name: "Cuenta de invitado", Status: "Vulnerable", Action: "guestoff", Current: "Activada", Detail: "La cuenta de invitado permite entrar al equipo sin contraseña propia."})
	}
	if s.SecureBoot != nil && !*s.SecureBoot {
		add(&Item{ID: "sec:sboot", Name: "Arranque seguro (Secure Boot)", Status: "Revisar", Current: "Desactivado",
			Detail: "Impide que un malware se cargue antes que Windows (bootkits). Se activa en la BIOS/UEFI del equipo."})
	}
	if s.Reboot {
		add(&Item{ID: "sec:reboot", Name: "Reinicio pendiente", Status: "Revisar", Action: "reboot", Current: "Pendiente",
			Detail: "Hay actualizaciones o cambios esperando a que reinicies. Hasta entonces no están aplicados."})
	}

	// ---- Endurecimiento: ajustes que usaría un atacante ----
	hard := func(id, name, sev string, bad bool, fix string, detail string, reboot bool) {
		it := &Item{ID: "hard:" + id, Category: "Endurecimiento", Name: name, Current: sev, Detail: detail, Reboot: reboot}
		if bad {
			it.Status, it.Action, it.Arg = ternary(sev == "Alta" || sev == "Crítica", "Vulnerable", "Revisar"), ternary(fix != "", "pentestfix", "none"), fix
		} else {
			it.Status = "Al día"
		}
		add(it)
	}
	hard("wdigest", "Contraseñas en memoria (WDigest)", "Alta", iv(s.WDigest, 0) == 1, "wdigest",
		"Con WDigest activo, Windows guarda las contraseñas en claro en la memoria y cualquier herramienta de robo de credenciales las puede leer.", false)
	hard("lmcompat", "Autenticación NTLMv1", "Alta", s.LMCompat != nil && *s.LMCompat < 3, "lmcompat",
		"Se permite NTLM antiguo, cuyas respuestas se descifran en minutos si alguien las captura en la red.", false)
	hard("llmnr", "Resolución de nombres LLMNR", "Media", iv(s.LLMNR, 1) != 0, "llmnr",
		"Si un nombre no existe, el equipo pregunta a toda la red y un atacante puede responder para robar el hash de la contraseña (Responder).", false)
	hard("ppl", "Protección de LSA (credenciales)", "Media", iv(s.PPL, 0) == 0, "ppl",
		"Ejecutar LSASS como proceso protegido impide que se vuelque su memoria para robar credenciales. Necesita reiniciar.", true)
	hard("autorun", "Reproducción automática de USB", "Baja", iv(s.AutoRun, 0) != 255, "autorun",
		"Las unidades extraíbles pueden lanzar contenido automáticamente al conectarse.", false)
	if s.PSv2 != "" {
		hard("psv2", "PowerShell 2.0", "Media", strings.EqualFold(s.PSv2, "Enabled"), "psv2",
			"Esta versión antigua no tiene registro de scripts ni AMSI: los atacantes la usan para saltarse el antivirus y los registros de PowerShell modernos.", false)
	}
	return l
}

// ---------- Programas (winget) ----------

func BuildPrograms(pk []WingetPkg, kev []KEVEntry) []*Item {
	var l []*Item
	for _, p := range pk {
		if p.Available == "" || p.ID == "" {
			continue
		}
		it := &Item{ID: "w:" + p.ID, Category: "Programas", Name: truncName(p.Name), Current: p.Version, Available: p.Available, Status: "Actualizar", Action: "winget", Arg: p.ID,
			Detail: fmt.Sprintf("Hay una versión nueva (%s). Se actualiza en segundo plano, sin abrir ventanas.", p.Available)}
		if p.Version == "Unknown" || p.Version == "Desconocido" || strings.HasPrefix(p.Version, "<") {
			it.Detail += " Windows no indica qué versión tienes instalada, así que winget la reinstalará en la última."
		}
		if p.Source != "" && p.Source != "winget" && p.Source != "msstore" {
			it.Detail += " Origen: " + p.Source + "."
		}
		if ks := kevRecent(it.Name, kev, 120); len(ks) > 0 {
			ids := []string{}
			for _, k := range ks {
				ids = append(ids, k.CVE)
			}
			sort.Strings(ids)
			it.Priority = "Alta"
			it.CVEs = ids
			it.Detail = fmt.Sprintf("CISA ha publicado hace poco %d fallo(s) de este programa que se están explotando de verdad. Actualízalo cuanto antes. ", len(ids)) + it.Detail
		}
		l = append(l, it)
	}
	return l
}

// ---------- Red: puertos abiertos ----------

type Listener struct {
	Addr  string `json:"a"`
	Port  int    `json:"p"`
	Proto string `json:"t"`
	Proc  string `json:"n"`
	Path  string `json:"x"`
	PID   int    `json:"pid"`
}

var riskyPorts = map[int][2]string{
	21:    {"FTP", "Transfiere archivos y contraseñas sin cifrar."},
	23:    {"Telnet", "Acceso remoto sin cifrar: cualquiera en la red puede ver las contraseñas."},
	135:   {"RPC", "Lo usan muchos ataques de movimiento lateral; no debería verse desde Internet."},
	139:   {"NetBIOS", "Compartición antigua de Windows."},
	445:   {"SMB (carpetas compartidas)", "Es la puerta que usan los ransomware para saltar de un equipo a otro."},
	3389:  {"Escritorio remoto", "Muy atacado con contraseñas probadas a fuerza bruta."},
	5900:  {"VNC", "Control remoto; muchas versiones sin cifrar."},
	5985:  {"WinRM (HTTP)", "Administración remota por PowerShell."},
	5986:  {"WinRM (HTTPS)", "Administración remota por PowerShell."},
	1433:  {"SQL Server", "Base de datos accesible desde la red."},
	3306:  {"MySQL", "Base de datos accesible desde la red."},
	5432:  {"PostgreSQL", "Base de datos accesible desde la red."},
	6379:  {"Redis", "Base de datos que a menudo no tiene contraseña."},
	27017: {"MongoDB", "Base de datos que a menudo no tiene contraseña."},
}

func BuildListeners(ls []Listener) []*Item {
	type key struct {
		port  int
		proto string
	}
	seen := map[key]*Item{}
	var l []*Item
	for _, x := range ls {
		if strings.HasPrefix(x.Addr, "127.") || x.Addr == "::1" || x.Port == 0 {
			continue
		}
		if x.Proto == "UDP" && riskyPorts[x.Port][0] == "" {
			continue // UDP: solo los conocidos, si no salen cientos
		}
		k := key{x.Port, x.Proto}
		if it, ok := seen[k]; ok {
			if x.Proc != "" && !strings.Contains(it.Current, x.Proc) {
				it.Current += ", " + x.Proc
			}
			continue
		}
		name := fmt.Sprintf("Puerto %d/%s", x.Port, x.Proto)
		it := &Item{ID: fmt.Sprintf("port:%s:%d", x.Proto, x.Port), Category: "Red", Name: name, Current: ternary(x.Proc != "", x.Proc, "Sistema"), Status: "Info",
			Detail: "Hay un programa esperando conexiones desde la red en este puerto."}
		if r, ok := riskyPorts[x.Port]; ok {
			it.Name = fmt.Sprintf("%s (puerto %d)", r[0], x.Port)
			it.Status = "Abierto"
			it.Detail = r[1] + " Comprueba que el firewall solo lo permite desde tu red o la VPN."
		}
		if x.Path != "" {
			it.Detail += "\nPrograma: " + x.Path
		}
		seen[k] = it
		l = append(l, it)
	}
	return l
}

// ---------- Intrusiones: inicios de sesión fallidos ----------

type FailedLogon struct {
	IP    string `json:"ip"`
	User  string `json:"user"`
	Count int    `json:"n"`
	Last  string `json:"last"`
}

func BuildIntrusions(fl []FailedLogon) []*Item {
	byIP := map[string]*FailedLogon{}
	users := map[string]map[string]bool{}
	for _, f := range fl {
		ip := f.IP
		if ip == "" || ip == "-" || ip == "::1" || ip == "127.0.0.1" {
			ip = "local"
		}
		x := byIP[ip]
		if x == nil {
			x = &FailedLogon{IP: ip}
			byIP[ip] = x
			users[ip] = map[string]bool{}
		}
		x.Count += f.Count
		if f.Last > x.Last {
			x.Last = f.Last
		}
		if f.User != "" {
			users[ip][f.User] = true
		}
	}
	var l []*Item
	for ip, x := range byIP {
		us := []string{}
		for u := range users[ip] {
			us = append(us, u)
		}
		sort.Strings(us)
		it := &Item{ID: "intr:" + ip, Category: "Intrusiones", Current: x.Last}
		if ip == "local" {
			if x.Count < 10 {
				continue
			}
			it.Name = fmt.Sprintf("%d contraseñas incorrectas en este equipo", x.Count)
			it.Status = "Revisar"
			it.Detail = "En las últimas 24 horas se ha fallado la contraseña muchas veces en este mismo equipo (usuarios: " + strings.Join(firstN(us, 5), ", ") + "). Puede ser alguien probando contraseñas o un programa con una contraseña antigua guardada."
		} else {
			if x.Count < 5 {
				continue
			}
			it.Name = fmt.Sprintf("%d intentos fallidos desde %s", x.Count, ip)
			it.Status = ternary(x.Count >= 20, "Vulnerable", "Revisar")
			it.Action, it.Arg = "blockip", ip
			it.Detail = "En las últimas 24 horas alguien desde " + ip + " ha intentado entrar con contraseñas incorrectas (usuarios probados: " + strings.Join(firstN(us, 5), ", ") + "). Si no reconoces esa dirección, bloquéala en el firewall."
		}
		l = append(l, it)
	}
	sort.Slice(l, func(a, b int) bool { return l[a].ID < l[b].ID })
	return l
}

// ---------- Limpieza ----------

type JunkDir struct {
	ID    string `json:"id"`
	Bytes int64  `json:"b"`
	Files int    `json:"f"`
}

var junkNames = map[string][2]string{
	"usertemp":    {"Archivos temporales del usuario", "Restos que dejan los programas al instalarse o trabajar. Se borran solo los que no están en uso."},
	"wintemp":     {"Archivos temporales de Windows", "Temporales del sistema y de instaladores."},
	"wudl":        {"Descargas antiguas de Windows Update", "Actualizaciones ya instaladas que Windows guardó al descargarlas."},
	"recycle":     {"Papelera de reciclaje", "Lo que has borrado y sigue ocupando espacio."},
	"crash":       {"Informes de errores y volcados de memoria", "Informes que Windows guarda cuando un programa se cierra solo."},
	"thumbs":      {"Caché de miniaturas", "Windows vuelve a crear las miniaturas cuando las necesita."},
	"delivery":    {"Optimización de distribución", "Trozos de actualizaciones que Windows comparte con otros equipos."},
	"edgecache":   {"Caché de Microsoft Edge", "Copias de páginas web; se vuelven a descargar al visitarlas."},
	"chromecache": {"Caché de Google Chrome", "Copias de páginas web; se vuelven a descargar al visitarlas."},
	"bravecache":  {"Caché de Brave", "Copias de páginas web; se vuelven a descargar al visitarlas."},
	"ffcache":     {"Caché de Firefox", "Copias de páginas web; se vuelven a descargar al visitarlas."},
}

// junkOrder: orden fijo para medir (el resultado se ordena luego por tamaño).
var junkOrder = []string{"usertemp", "wintemp", "wudl", "recycle", "crash", "thumbs", "delivery", "edgecache", "chromecache", "bravecache", "ffcache"}

func BuildJunk(d []JunkDir) []*Item {
	var l []*Item
	for _, j := range d {
		n, ok := junkNames[j.ID]
		if !ok || j.Bytes < 1<<20 {
			continue
		}
		it := &Item{ID: "junk:" + j.ID, Category: "Limpieza", Name: n[0], Detail: n[1], Bytes: j.Bytes, Current: fmtBytes(j.Bytes), Action: "clean", Arg: j.ID,
			Status: ternary(j.Bytes >= 50<<20, "Limpiable", "Info")}
		l = append(l, it)
	}
	sort.Slice(l, func(a, b int) bool { return l[a].Bytes > l[b].Bytes })
	return l
}

// ---------- Hardware ----------

type DiskHW struct {
	Name    string `json:"name"`
	Media   string `json:"media"`
	Health  string `json:"health"`
	Size    int64  `json:"size"`
	Wear    *int   `json:"wear"`
	Temp    *int   `json:"temp"`
	ReadErr *int64 `json:"readErr"`
}

type HWInfo struct {
	Disks     []DiskHW `json:"disks"`
	BatDesign int64    `json:"batDesign"`
	BatFull   int64    `json:"batFull"`
	SysFree   int64    `json:"sysFree"`
	SysSize   int64    `json:"sysSize"`
}

func BuildHardware(h HWInfo) []*Item {
	var l []*Item
	for i, d := range h.Disks {
		it := &Item{ID: fmt.Sprintf("hw:disk:%d", i), Category: "Hardware", Name: strings.TrimSpace(d.Name), Current: strings.TrimSpace(d.Media + " · " + fmtBytes(d.Size)), Status: "Al día",
			Detail: "El disco informa de que está en buen estado."}
		if it.Name == "" {
			it.Name = fmt.Sprintf("Disco %d", i)
		}
		switch {
		case d.Health != "" && d.Health != "Healthy":
			it.Status = "Vulnerable"
			it.Detail = "El propio disco avisa de un problema (" + d.Health + "). Haz una copia de seguridad cuanto antes y plantéate cambiarlo."
		case d.Wear != nil && *d.Wear >= 90:
			it.Status = "Revisar"
			it.Detail = fmt.Sprintf("El SSD ha consumido el %d %% de su vida útil estimada. Ve pensando en cambiarlo.", *d.Wear)
		case d.ReadErr != nil && *d.ReadErr > 0:
			it.Status = "Revisar"
			it.Detail = fmt.Sprintf("El disco ha registrado %d errores de lectura sin corregir.", *d.ReadErr)
		case d.Temp != nil && *d.Temp >= 65:
			it.Status = "Revisar"
			it.Detail = fmt.Sprintf("El disco está a %d °C. Revisa la ventilación.", *d.Temp)
		}
		if d.Wear != nil && it.Status == "Al día" {
			it.Detail += fmt.Sprintf(" Desgaste: %d %%.", *d.Wear)
		}
		if d.Temp != nil && it.Status == "Al día" {
			it.Detail += fmt.Sprintf(" Temperatura: %d °C.", *d.Temp)
		}
		l = append(l, it)
	}
	if h.BatDesign > 0 && h.BatFull > 0 {
		pct := int(100 * h.BatFull / h.BatDesign)
		it := &Item{ID: "hw:bat", Category: "Hardware", Name: "Batería", Current: fmt.Sprintf("%d %% de su capacidad original", pct), Status: "Al día",
			Detail: "La batería conserva buena parte de su capacidad."}
		if pct < 60 {
			it.Status = "Revisar"
			it.Detail = "La batería ya solo carga el " + fmt.Sprint(pct) + " % de lo que cargaba nueva. Durará bastante menos lejos del enchufe."
		}
		l = append(l, it)
	}
	if h.SysSize > 0 {
		pct := int(100 * h.SysFree / h.SysSize)
		it := &Item{ID: "hw:sysfree", Category: "Hardware", Name: "Espacio en el disco del sistema", Current: fmtBytes(h.SysFree) + " libres", Status: "Al día", Detail: "Hay espacio suficiente para que Windows funcione y se actualice."}
		if pct < 10 || h.SysFree < 15<<30 {
			it.Status = "Revisar"
			it.Detail = "Queda poco espacio. Windows necesita unos 20 GB libres para actualizarse bien. Mira el apartado Limpieza."
		}
		l = append(l, it)
	}
	return l
}

// ---------- Eventos ----------

type EvGroup struct {
	Kind  string `json:"k"`
	Count int    `json:"n"`
	Last  string `json:"last"`
	Extra string `json:"x"`
}

var evNames = map[string][3]string{
	"power41":   {"Apagados inesperados", "Vulnerable", "Windows se ha reiniciado sin apagarse bien (corte de luz, cuelgue o botón de encendido). Si se repite, puede ser la fuente, la batería o el sobrecalentamiento."},
	"bugcheck":  {"Pantallazos azules", "Vulnerable", "Windows se ha bloqueado con un error grave. Suele ser un controlador, la memoria RAM o el disco."},
	"disk":      {"Errores del disco", "Vulnerable", "El disco ha devuelto errores de lectura o escritura. Haz copia de seguridad y revisa su salud en Hardware."},
	"whea":      {"Errores de hardware (WHEA)", "Revisar", "El procesador, la memoria o el bus PCI han informado de errores corregidos o graves."},
	"appcrash":  {"Programas que se cierran solos", "Info", "Programas que han fallado y se han cerrado."},
	"svcfail":   {"Servicios que se paran solos", "Revisar", "Servicios de Windows o de programas que se han detenido de forma inesperada."},
	"defthreat": {"Amenazas detectadas por Defender", "Revisar", "Microsoft Defender ha encontrado y bloqueado malware en este equipo."},
	"newsvc":    {"Servicios nuevos instalados", "Info", "Se han instalado servicios nuevos. Comprueba que los reconoces."},
	"logclear":  {"Registro de seguridad borrado", "Vulnerable", "Alguien ha vaciado el registro de seguridad de Windows. Es algo que hacen los atacantes para borrar sus huellas."},
}

func BuildEvents(g []EvGroup) []*Item {
	var l []*Item
	for _, e := range g {
		n, ok := evNames[e.Kind]
		if !ok || e.Count == 0 {
			continue
		}
		st := n[1]
		if e.Kind == "appcrash" && e.Count >= 10 {
			st = "Revisar"
		}
		it := &Item{ID: "ev:" + e.Kind, Category: "Eventos", Name: fmt.Sprintf("%s (%d en 7 días)", n[0], e.Count), Status: st, Current: e.Last, Detail: n[2]}
		if e.Extra != "" {
			it.Detail += "\n\n" + e.Extra
		}
		l = append(l, it)
	}
	return l
}

// ---------- Cambios: persistencia (inicio, tareas, servicios, administradores) ----------

type PersistEntry struct {
	Kind string `json:"k"` // run | task | service | admin
	Name string `json:"n"`
	Cmd  string `json:"c"`
}

func persistKey(p PersistEntry) string {
	return p.Kind + "|" + strings.ToLower(p.Name) + "|" + strings.ToLower(p.Cmd)
}

var persistKind = map[string]string{"run": "Programa de inicio nuevo", "task": "Tarea programada nueva", "service": "Servicio nuevo", "admin": "Administrador nuevo"}

// BuildChanges compara con la foto anterior. Si no hay foto anterior no avisa de nada.
func BuildChanges(now []PersistEntry, base map[string]bool) []*Item {
	if base == nil {
		return nil
	}
	var l []*Item
	for _, p := range now {
		k := persistKey(p)
		if base[k] {
			continue
		}
		it := &Item{ID: "chg:" + k, Category: "Cambios", Name: persistKind[p.Kind] + ": " + p.Name, Status: "Revisar", Action: "acceptchange", Arg: k, Current: "Nuevo",
			Detail: "Ha aparecido desde el análisis anterior. Si lo has instalado tú o es de un programa conocido, pulsa Aceptar.\n\n" + p.Cmd}
		if p.Kind == "admin" {
			it.Status = "Vulnerable"
			it.Detail = "Se ha añadido una cuenta al grupo de administradores de este equipo. Si no lo has hecho tú, puede ser un atacante dándose permisos.\n\n" + p.Cmd
		}
		lc := strings.ToLower(p.Cmd)
		if hasAnyR(lc, "persistencia_sospechosa") {
			it.Status = "Vulnerable"
			it.Detail = "Se ejecuta desde una carpeta temporal o con órdenes ocultas: es como se instala el malware para volver a arrancar.\n\n" + p.Cmd
		}
		l = append(l, it)
	}
	return l
}
