package main

// Dispositivos conectados (ratones, teclados, cascos, pantallas, USB, Bluetooth…) a partir
// de la lista de Plug and Play de Windows. Se agrupan por «contenedor» (un aparato físico
// puede tener varias funciones: unos cascos son audio + controles HID + Bluetooth).

import (
	"regexp"
	"sort"
	"strings"
)

type PnPDev struct {
	Instance  string `json:"instance"`
	Class     string `json:"class"`
	Name      string `json:"name"`
	BusDesc   string `json:"busDesc"`
	Mfg       string `json:"mfg"`
	Enum      string `json:"enum"`
	Container string `json:"container"`
	Problem   uint32 `json:"problem"`
	Disabled  bool   `json:"disabled"`
	DrvVer    string `json:"drvVer"`
	DrvProv   string `json:"drvProv"`
	FwVer     string `json:"fwVer"`
	Location  string `json:"location"`
}

type DevGroup struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Cat      string   `json:"cat"`
	Conn     string   `json:"conn"`   // USB, Bluetooth, Vídeo, Red…
	Status   string   `json:"status"` // ok | problema | desactivado
	Problem  string   `json:"problem,omitempty"`
	Mfg      string   `json:"mfg"`
	VidPid   string   `json:"vidPid,omitempty"`
	DrvVer   string   `json:"drvVer,omitempty"`
	FwVer    string   `json:"fwVer,omitempty"`
	Funcs    []string `json:"funcs"`
	Internal bool     `json:"internal"`
	Parts    []PnPDev `json:"parts"`
}

// el contenedor del propio PC: lo que está dentro del equipo
const pcContainer = "{00000000-0000-0000-ffff-ffffffffffff}"

var reVidPid = regexp.MustCompile(`(?i)VID_([0-9A-F]{4}).*PID_([0-9A-F]{4})`)

// classNames: categoría y función en español para cada clase de Windows.
var classNames = map[string][2]string{
	"mouse": {"Ratones y punteros", "Ratón"}, "keyboard": {"Teclados", "Teclado"}, "audioendpoint": {"Audio", "Audio"}, "media": {"Audio", "Sonido"},
	"monitor": {"Pantallas", "Pantalla"}, "camera": {"Cámaras", "Cámara"}, "image": {"Cámaras y escáneres", "Imagen"}, "printer": {"Impresoras", "Impresora"},
	"printqueue": {"Impresoras", "Cola de impresión"}, "diskdrive": {"Almacenamiento", "Disco"}, "wpd": {"Teléfonos y almacenamiento", "Dispositivo portátil"},
	"bluetooth": {"Bluetooth", "Bluetooth"}, "hidclass": {"Dispositivos de entrada", "Control HID"}, "net": {"Red", "Adaptador de red"}, "usb": {"USB", "USB"},
	"display": {"Tarjetas gráficas", "Gráfica"}, "biometric": {"Seguridad", "Huella / rostro"}, "smartcardreader": {"Seguridad", "Lector de tarjetas"},
	"sensor": {"Sensores", "Sensor"}, "battery": {"Batería", "Batería"}, "volume": {"Almacenamiento", "Volumen"}, "cdrom": {"Almacenamiento", "Lector óptico"},
	"xnacompositedevice": {"Mandos de juego", "Mando"}, "hidgamecontroller": {"Mandos de juego", "Mando"}, "ports": {"Puertos", "Puerto serie"},
	"processor": {"Procesador", "Procesador"}, "system": {"Sistema", "Componente del sistema"}, "softwaredevice": {"Software", "Dispositivo de software"},
	"scsiadapter": {"Controladoras de almacenamiento", "Controladora"}, "hdc": {"Controladoras de almacenamiento", "Controladora"}, "firmware": {"Firmware", "Firmware"},
	"securitydevices": {"Seguridad", "Chip TPM"}, "computer": {"Sistema", "Equipo"}, "audioprocessingobject": {"Audio", "Efecto de audio"},
}

func classInfo(class string) (cat, fn string) {
	if v, ok := classNames[strings.ToLower(class)]; ok {
		return v[0], v[1]
	}
	if class == "" {
		return "Otros", "Dispositivo"
	}
	return "Otros", class
}

// ProblemText traduce los códigos de problema del Administrador de dispositivos.
func ProblemText(code uint32) string {
	switch code {
	case 0:
		return ""
	case 1, 3:
		return "El controlador no está bien instalado"
	case 10:
		return "No se puede iniciar (código 10)"
	case 12:
		return "Conflicto de recursos con otro dispositivo (código 12)"
	case 14:
		return "Hay que reiniciar el equipo (código 14)"
	case 18, 28:
		return "Falta el controlador (código " + itoa(int(code)) + ")"
	case 22:
		return "Desactivado"
	case 24:
		return "No está presente o no funciona (código 24)"
	case 31:
		return "Windows no puede cargar su controlador (código 31)"
	case 39:
		return "El controlador está dañado o falta (código 39)"
	case 43:
		return "Windows lo ha detenido porque informó de un problema (código 43)"
	case 45:
		return "No está conectado ahora (código 45)"
	case 52:
		return "El controlador no tiene una firma válida (código 52)"
	}
	return "Tiene un problema (código " + itoa(int(code)) + ")"
}

func connOf(parts []PnPDev) string {
	has := func(sub ...string) bool {
		for _, p := range parts {
			e := strings.ToUpper(p.Enum + "\\" + p.Instance)
			for _, s := range sub {
				if strings.Contains(e, s) {
					return true
				}
			}
		}
		return false
	}
	switch {
	case has("BTHENUM", "BTHLE", "BTHLEDEVICE", "BTHHFENUM", "{00001812-", "BTHA2DP"):
		return "Bluetooth"
	case has("USBSTOR", "USB\\", "VID_"):
		return "USB"
	case has("DISPLAY\\"):
		return "Vídeo (HDMI / DisplayPort)"
	case has("PRINTENUM", "WSDPRINT", "TCPMON"):
		return "Red o USB"
	case has("HDAUDIO", "INTELAUDIO"):
		return "Audio integrado"
	case has("PCI\\"):
		return "Interno (PCI)"
	}
	return "Interno"
}

// bestName elige el nombre más reconocible del aparato.
func bestName(parts []PnPDev) string {
	score := func(p PnPDev) int {
		n := strings.ToLower(p.Name)
		switch {
		case strings.HasPrefix(strings.ToUpper(p.Enum), "BTHENUM") && !strings.Contains(n, "servicio") && !strings.Contains(n, "service") && !strings.Contains(n, "avrcp") && !strings.Contains(n, "a2dp"):
			return 9
		case strings.HasPrefix(strings.ToUpper(p.Enum), "BTHLE") && !strings.Contains(n, "generic"):
			return 8
		case p.BusDesc != "" && !hasAny(strings.ToLower(p.BusDesc), "usb composite", "input device", "hub"):
			return 7
		case strings.ToLower(p.Class) == "monitor" || strings.ToLower(p.Class) == "printer":
			return 7
		case strings.ToLower(p.Class) == "audioendpoint":
			return 6
		case hasAny(n, "hid-compliant", "compatible con hid", "dispositivo de entrada usb", "usb input device", "usb composite", "dispositivo compuesto", "vendor-defined", "definido por el proveedor", "consumer control", "control de consumidor", "system controller"):
			return 1
		}
		return 4
	}
	best, bs := "", -1
	for _, p := range parts {
		n := p.Name
		if s := score(p); s == 7 && p.BusDesc != "" && strings.ToLower(p.Class) != "monitor" && strings.ToLower(p.Class) != "printer" {
			n = p.BusDesc
		}
		if n == "" {
			continue
		}
		if s := score(p); s > bs {
			best, bs = n, s
		}
	}
	return best
}

func groupCat(parts []PnPDev, name string) string {
	cls := map[string]bool{}
	for _, p := range parts {
		cls[strings.ToLower(p.Class)] = true
	}
	n := strings.ToLower(name)
	switch {
	case cls["audioendpoint"] || cls["media"]:
		if hasAny(n, "auricular", "headset", "headphone", "cascos", "buds", "airpods", "wh-", "wf-", "hands-free", "manos libres") {
			return "Auriculares y cascos"
		}
		if hasAny(n, "micrófono", "microphone", "mic") && !cls["mouse"] {
			return "Micrófonos"
		}
		if cls["mouse"] || cls["keyboard"] {
			break
		}
		return "Audio"
	case cls["monitor"]:
		return "Pantallas"
	case cls["xnacompositedevice"] || cls["hidgamecontroller"] || hasAny(n, "controller", "mando", "gamepad", "xbox"):
		return "Mandos de juego"
	}
	switch {
	case cls["mouse"]:
		return "Ratones y punteros"
	case cls["keyboard"]:
		return "Teclados"
	case cls["camera"] || cls["image"]:
		return "Cámaras y escáneres"
	case cls["printer"] || cls["printqueue"]:
		return "Impresoras"
	case cls["diskdrive"] || cls["wpd"] || cls["volume"]:
		return "Almacenamiento y teléfonos"
	case cls["biometric"] || cls["smartcardreader"]:
		return "Seguridad"
	case cls["net"]:
		return "Red"
	case cls["bluetooth"]:
		return "Bluetooth"
	}
	return "Otros"
}

// GroupDevices agrupa por aparato físico. Lo interno del PC se agrupa por clase.
func GroupDevices(l []PnPDev) (ext []DevGroup, internal []DevGroup) {
	byC := map[string][]PnPDev{}
	var order []string
	for _, d := range l {
		c := strings.ToLower(d.Container)
		if c == "" || c == pcContainer {
			cat, fn := classInfo(d.Class)
			g := DevGroup{ID: d.Instance, Name: d.Name, Cat: cat, Conn: connOf([]PnPDev{d}), Mfg: d.Mfg, DrvVer: d.DrvVer, FwVer: d.FwVer, Funcs: []string{fn}, Internal: true, Parts: []PnPDev{d}}
			setStatus(&g, []PnPDev{d})
			internal = append(internal, g)
			continue
		}
		if _, ok := byC[c]; !ok {
			order = append(order, c)
		}
		byC[c] = append(byC[c], d)
	}
	for _, c := range order {
		parts := byC[c]
		name := bestName(parts)
		if name == "" {
			continue
		}
		g := DevGroup{ID: c, Name: name, Conn: connOf(parts), Parts: parts}
		g.Cat = groupCat(parts, name)
		fseen := map[string]bool{}
		for _, p := range parts {
			_, fn := classInfo(p.Class)
			if !fseen[fn] && fn != "Dispositivo de software" && fn != "USB" {
				fseen[fn] = true
				g.Funcs = append(g.Funcs, fn)
			}
			if g.Mfg == "" && p.Mfg != "" && !hasAny(strings.ToLower(p.Mfg), "(standard", "(estándar", "microsoft", "generic", "genérico") {
				g.Mfg = p.Mfg
			}
			if g.DrvVer == "" && p.DrvVer != "" && !strings.EqualFold(p.DrvProv, "Microsoft") {
				g.DrvVer = p.DrvVer
			}
			if g.FwVer == "" && p.FwVer != "" {
				g.FwVer = p.FwVer
			}
			if g.VidPid == "" {
				if m := reVidPid.FindStringSubmatch(p.Instance); m != nil {
					g.VidPid = strings.ToUpper(m[1] + ":" + m[2])
				}
			}
		}
		if g.DrvVer == "" {
			for _, p := range parts {
				if p.DrvVer != "" {
					g.DrvVer = p.DrvVer
					break
				}
			}
		}
		if g.Mfg == "" {
			for _, p := range parts {
				if p.Mfg != "" {
					g.Mfg = p.Mfg
					break
				}
			}
		}
		setStatus(&g, parts)
		ext = append(ext, g)
	}
	sort.SliceStable(ext, func(a, b int) bool {
		if (ext[a].Status != "ok") != (ext[b].Status != "ok") {
			return ext[a].Status != "ok"
		}
		if ext[a].Cat != ext[b].Cat {
			return ext[a].Cat < ext[b].Cat
		}
		return ext[a].Name < ext[b].Name
	})
	sort.SliceStable(internal, func(a, b int) bool {
		if (internal[a].Status != "ok") != (internal[b].Status != "ok") {
			return internal[a].Status != "ok"
		}
		if internal[a].Cat != internal[b].Cat {
			return internal[a].Cat < internal[b].Cat
		}
		return internal[a].Name < internal[b].Name
	})
	return
}

func setStatus(g *DevGroup, parts []PnPDev) {
	g.Status = "ok"
	for _, p := range parts {
		if p.Disabled || p.Problem == 22 {
			if g.Status == "ok" {
				g.Status, g.Problem = "desactivado", "Desactivado en el Administrador de dispositivos"
			}
			continue
		}
		if p.Problem != 0 && p.Problem != 45 {
			g.Status, g.Problem = "problema", ProblemText(p.Problem)+ternary(len(parts) > 1, " · "+p.Name, "")
			return
		}
	}
}
