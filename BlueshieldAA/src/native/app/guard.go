package main

// Anti-ransomware 4.x: documentos trampa, órdenes previas al cifrado y modo contención.
// Parte portable (con tests). Lo que toca Windows está en guard_windows.go.

import (
	"archive/zip"
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GuardConfig: lo que decide el administrador desde la ventana (guardian.json).
type GuardConfig struct {
	Enabled    bool     `json:"enabled"`
	Mode       string   `json:"mode"` // "simulacro" (solo avisa y apunta) | "contener"
	Isolate    bool     `json:"isolate"`
	StopSvc    bool     `json:"stopSvc"`
	Lockdown   bool     `json:"lockdown"`
	Custom     []string `json:"custom"`
	InstallDir string   `json:"installDir"`
	Marker     string   `json:"marker"`
}

func DefaultGuardConfig() GuardConfig {
	return GuardConfig{Mode: "simulacro", Isolate: true, StopSvc: true, Lockdown: true, Custom: []string{}}
}

// GuardRuntime: lo que escribe el guardián (guardian-estado.json).
type GuardRuntime struct {
	Beat    time.Time     `json:"beat"`
	PID     int           `json:"pid"`
	Version string        `json:"version"`
	Folders []GuardFolder `json:"folders"`
	Decoys  []Decoy       `json:"decoys"`
	Errors  []string      `json:"errors"`
}

type GuardFolder struct {
	Path string `json:"path"`
	N    int    `json:"n"`
}

type Decoy struct {
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"`
}

type Culprit struct {
	PID         int    `json:"pid"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	Cmd         string `json:"cmd,omitempty"`
	Why         string `json:"why"`
	Suspended   bool   `json:"suspended"`
	Quarantined bool   `json:"quarantined"`
	QID         string `json:"qid,omitempty"`
}

type SvcState struct {
	Name      string `json:"name"`
	Display   string `json:"display"`
	StartType uint32 `json:"startType"`
	Running   bool   `json:"running"`
}

// Containment: estado de la cuarentena del equipo (contencion.json). Sobrevive a reinicios.
type Containment struct {
	Active     bool       `json:"active"`
	Simulated  bool       `json:"simulated"`
	Since      time.Time  `json:"since"`
	Reason     string     `json:"reason"`
	Incident   string     `json:"incident"`
	Culprits   []Culprit  `json:"culprits"`
	Isolated   bool       `json:"isolated"`
	FwBackup   string     `json:"fwBackup,omitempty"`
	Services   []SvcState `json:"services"`
	Killed     []string   `json:"killed"`
	Released   time.Time  `json:"released"`
	ReleasedBy string     `json:"releasedBy,omitempty"`
	Errors     []string   `json:"errors"`
}

type GuardIncident struct {
	ID        string    `json:"id"`
	When      time.Time `json:"when"`
	Reason    string    `json:"reason"`
	Kind      string    `json:"kind"` // "ataque" | "aviso" | "prueba" | "orden"
	Simulated bool      `json:"simulated"`
	Files     []string  `json:"files"`
	NewNames  []string  `json:"newNames"`
	Culprits  []Culprit `json:"culprits"`
	Contained bool      `json:"contained"`
	WouldKill []string  `json:"wouldKill"`
	WouldStop []string  `json:"wouldStop"`
	Isolated  bool      `json:"isolated"`
	Ms        int       `json:"ms"`
	Resolved  bool      `json:"resolved"`
}

// GuardOrder: lo que la ventana pide al guardián (carpeta "ordenes").
type GuardOrder struct {
	Cmd  string    `json:"cmd"` // "prueba" | "liberar" | "resolver" | "resembrar"
	Arg  string    `json:"arg,omitempty"`
	By   string    `json:"by,omitempty"`
	When time.Time `json:"when"`
}

// ---------- documentos trampa ----------

// Nombres que quedan los primeros o los últimos de la carpeta (por ahí empieza a cifrar un ransomware).
var decoyNames = []string{"!0000_Presupuesto_2026.docx", "!0000_Facturas_pendientes.xlsx", "zzzz_Contrato_firmado.pdf", "zzzz_Claves_banco.txt", "!0000_Foto_DNI.jpg"}

// DecoyBytes genera un documento trampa VÁLIDO (se abre bien) de cada tipo.
func DecoyBytes(name, marker string) []byte {
	ext := strings.ToLower(filepath.Ext(name))
	note := "Documento de control de BlueShieldAA (" + marker + "). No lo borres ni lo muevas: sirve para detectar ransomware."
	switch ext {
	case ".docx":
		return ooxml(map[string]string{
			"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
			"_rels/.rels":         `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`,
			"word/document.xml":   `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Presupuesto 2026</w:t></w:r></w:p><w:p><w:r><w:t>` + note + `</w:t></w:r></w:p></w:body></w:document>`,
		})
	case ".xlsx":
		return ooxml(map[string]string{
			"[Content_Types].xml":        `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`,
			"_rels/.rels":                `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`,
			"xl/workbook.xml":            `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Facturas" sheetId="1" r:id="rId1"/></sheets></workbook>`,
			"xl/_rels/workbook.xml.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`,
			"xl/worksheets/sheet1.xml":   `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>` + note + `</t></is></c></row><row r="2"><c r="A2"><v>1250.5</v></c></row></sheetData></worksheet>`,
		})
	case ".pdf":
		body := "BT /F1 12 Tf 50 750 Td (Contrato firmado - " + marker + ") Tj ET"
		var b bytes.Buffer
		offs := []int{}
		w := func(s string) { b.WriteString(s) }
		w("%PDF-1.4\n")
		objs := []string{
			"<< /Type /Catalog /Pages 2 0 R >>",
			"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
			fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(body), body),
			"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
		}
		for i, o := range objs {
			offs = append(offs, b.Len())
			w(fmt.Sprintf("%d 0 obj\n%s\nendobj\n", i+1, o))
		}
		x := b.Len()
		w(fmt.Sprintf("xref\n0 %d\n0000000000 65535 f \n", len(objs)+1))
		for _, o := range offs {
			w(fmt.Sprintf("%010d 00000 n \n", o))
		}
		w(fmt.Sprintf("trailer << /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, x))
		return b.Bytes()
	case ".jpg":
		img := image.NewRGBA(image.Rect(0, 0, 320, 200))
		for y := 0; y < 200; y++ {
			for x := 0; x < 320; x++ {
				img.Set(x, y, color.RGBA{uint8(40 + x/4), uint8(80 + y/3), 160, 255})
			}
		}
		var b bytes.Buffer
		_ = jpeg.Encode(&b, img, &jpeg.Options{Quality: 80})
		return b.Bytes()
	}
	return []byte("Claves del banco (no compartir)\r\nUsuario: ********\r\n" + note + "\r\n")
}

func ooxml(parts map[string]string) []byte {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, n := range []string{"[Content_Types].xml", "_rels/.rels"} {
		w, _ := z.Create(n)
		w.Write([]byte(parts[n]))
	}
	for n, c := range parts {
		if n == "[Content_Types].xml" || n == "_rels/.rels" {
			continue
		}
		w, _ := z.Create(n)
		w.Write([]byte(c))
	}
	z.Close()
	return b.Bytes()
}

// FolderAllowed: solo carpetas locales del equipo (nunca nube, red ni otros perfiles).
func FolderAllowed(p string) (bool, string) {
	l := strings.ToLower(p)
	switch {
	case strings.HasPrefix(l, `\\`):
		return false, "es una carpeta de red"
	case hasAny(l, "onedrive", "sharepoint", "dropbox", "google drive", "icloud", "box sync", "nextcloud"):
		return false, "es una carpeta sincronizada con la nube"
	case hasAny(l, `\appdata\`, `\temp`, `\windows\`, `\program files`, `\programdata\`):
		return false, "es una carpeta del sistema o temporal"
	case strings.Contains(l, ".adm"):
		return false, "es el perfil de la cuenta de administración"
	}
	return true, ""
}

type DecoyEvent struct {
	Path    string
	Kind    string // "modificado", "renombrado", "borrado"
	NewName string
}

// CheckDecoys compara los documentos trampa con cómo se dejaron.
func CheckDecoys(list []Decoy) []DecoyEvent {
	var ev []DecoyEvent
	for _, d := range list {
		fi, err := os.Stat(d.Path)
		if err == nil {
			if fi.Size() != d.Size || fi.ModTime().Unix() != d.MTime {
				ev = append(ev, DecoyEvent{Path: d.Path, Kind: "modificado"})
			}
			continue
		}
		// ¿lo han renombrado? (ransomware: Presupuesto.docx → Presupuesto.docx.locked)
		dir, base := filepath.Dir(d.Path), filepath.Base(d.Path)
		stem := strings.TrimSuffix(base, filepath.Ext(base))
		renamed := ""
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				if n := e.Name(); n != base && strings.HasPrefix(n, stem) {
					renamed = n
					break
				}
			}
		}
		if renamed != "" {
			ev = append(ev, DecoyEvent{Path: d.Path, Kind: "renombrado", NewName: renamed})
		} else {
			ev = append(ev, DecoyEvent{Path: d.Path, Kind: "borrado"})
		}
	}
	return ev
}

// IsAttack decide si los cambios son un ataque claro (no un borrado suelto a mano).
func IsAttack(ev []DecoyEvent) bool {
	del := 0
	for _, e := range ev {
		if e.Kind != "borrado" {
			return true
		}
		del++
	}
	return del >= 2
}

// RansomCommand: órdenes que el ransomware lanza antes de cifrar (borrar copias, quitar la recuperación…).
func RansomCommand(cmd string) string {
	c := strings.ToLower(strings.Join(strings.Fields(cmd), " "))
	for _, k := range rule("guardian_ordenes") {
		if strings.Contains(c, k) {
			return k
		}
	}
	return ""
}

// AllowedInLockdown: qué se puede ejecutar mientras el equipo está en contención.
func AllowedInLockdown(name, path, signed, company string, cfg *GuardConfig, parentIsUs bool) bool {
	return lockdownWhy(name, path, signed, company, cfg, parentIsUs) == ""
}

// lockdownWhy devuelve "" si se permite, o el motivo por el que se cierra.
func lockdownWhy(name, path, signed, company string, cfg *GuardConfig, parentIsUs bool) string {
	n := strings.ToLower(name)
	if path == "" || n == "system" || n == "registry" || n == "secure system" || n == "memory compression" {
		return "" // procesos protegidos del sistema
	}
	if cfg.InstallDir != "" && strings.HasPrefix(strings.ToLower(path), strings.ToLower(cfg.InstallDir)+`\`) {
		return ""
	}
	if parentIsUs {
		return ""
	}
	// procesos imprescindibles de Windows: cerrarlos dejaría el equipo colgado o con pantallazo azul
	lp := strings.ToLower(path)
	if strings.Contains(lp, `:\windows\`) && hasAny(n, "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "smss.exe", "svchost.exe", "dwm.exe", "explorer.exe", "fontdrvhost.exe", "logonui.exe", "sihost.exe", "ctfmon.exe", "conhost.exe", "taskhostw.exe", "runtimebroker.exe", "searchhost.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe", "textinputhost.exe", "lsaiso.exe", "audiodg.exe", "spoolsv.exe", "wudfhost.exe", "dllhost.exe", "securityhealthservice.exe", "securityhealthsystray.exe", "taskmgr.exe") {
		return ""
	}
	if inList(n, "contencion_bloquear") {
		return "herramienta de Windows que usa el ransomware"
	}
	if signed == "Microsoft" {
		return ""
	}
	if signed == "Firmado" && TrustedVendor(company) {
		return ""
	}
	if signed == "Firmado" {
		return "programa que no es de Microsoft"
	}
	return "programa sin firma digital válida"
}

// TrustedVendor: antivirus y fabricantes de hardware que siguen funcionando en contención.
func TrustedVendor(company string) bool {
	lc := strings.ToLower(company)
	if lc == "" {
		return false
	}
	for _, v := range rule("contencion_empresas") {
		if strings.Contains(lc, v) {
			return true
		}
	}
	return false
}

// MustStopService: servicios que se paran en contención (red/compartición y los que no son de Microsoft).
func MustStopService(name, signed, company string) string {
	if inList(strings.ToLower(name), "contencion_servicios") {
		return "comparte o abre el equipo a la red"
	}
	if signed == "Microsoft" || signed == "" {
		return ""
	}
	if signed == "Firmado" && TrustedVendor(company) {
		return ""
	}
	return "servicio que no es de Microsoft"
}

// ServiceExe saca la ruta del ejecutable de la línea de un servicio.
func ServiceExe(bin string, sysRoot string) string {
	b := strings.TrimSpace(bin)
	if sysRoot != "" {
		for _, v := range []string{"%systemroot%", "%windir%"} {
			if i := strings.Index(strings.ToLower(b), v); i >= 0 {
				b = b[:i] + sysRoot + b[i+len(v):]
			}
		}
		if strings.HasPrefix(strings.ToLower(b), `\systemroot\`) {
			b = sysRoot + b[len(`\systemroot`):]
		}
	}
	if strings.HasPrefix(b, `"`) {
		if i := strings.Index(b[1:], `"`); i >= 0 {
			return b[1 : i+1]
		}
		return strings.Trim(b, `"`)
	}
	if i := strings.Index(strings.ToLower(b), ".exe"); i >= 0 {
		return b[:i+4]
	}
	if i := strings.IndexByte(b, ' '); i > 0 {
		return b[:i]
	}
	return b
}

// ---------- salir de la cuarentena ----------

type ScanState struct {
	Running bool      `json:"running"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	Code    int       `json:"code"`
	OK      bool      `json:"ok"`
	Error   string    `json:"error,omitempty"`
	Tail    []string  `json:"tail"`
}

type ReleaseCheck struct {
	ID     string   `json:"id"`
	Title  string   `json:"title"`
	Detail string   `json:"detail"`
	OK     bool     `json:"ok"`
	Need   bool     `json:"need"`
	List   []string `json:"list,omitempty"`
}

// ReleaseChecks: la lista de comprobación para liberar el equipo.
func ReleaseChecks(c Containment, scan ScanState, running []string, persist []string, newAttacks int, reviewed, externalAV bool) []ReleaseCheck {
	var out []ReleaseCheck
	cul := ReleaseCheck{ID: "culpable", Title: "El programa culpable está detenido", Need: true, OK: len(running) == 0, List: running}
	switch {
	case len(running) > 0:
		cul.Detail = "Sigue en marcha: " + strings.Join(running, ", ")
	case len(c.Culprits) == 0:
		cul.Detail = "No se identificó un programa concreto; el bloqueo ha cerrado todo lo que no es de Microsoft."
	default:
		q := 0
		for _, x := range c.Culprits {
			if x.Quarantined {
				q++
			}
		}
		cul.Detail = fmt.Sprintf("%d detenido(s), %d en cuarentena.", len(c.Culprits), q)
	}
	out = append(out, cul)

	sc := ReleaseCheck{ID: "analisis", Title: "Análisis completo del antivirus sin amenazas", Need: true}
	switch {
	case externalAV:
		sc.OK, sc.Detail = true, "Indicado por el administrador: analizado con otro antivirus."
	case scan.Running:
		sc.Detail = "Analizando desde " + scan.Start.Format("15:04") + "… (puede tardar más de una hora)"
	case scan.End.IsZero() || scan.End.Before(c.Since):
		sc.Detail = "Falta hacerlo después de la detección."
	case scan.Error != "":
		sc.Detail = scan.Error
	case scan.OK:
		sc.OK, sc.Detail = true, "Microsoft Defender no encontró amenazas ("+scan.End.Format("02/01 15:04")+")."
	default:
		sc.Detail = "Microsoft Defender ha encontrado amenazas: revísalas en Seguridad de Windows y vuelve a analizar."
	}
	out = append(out, sc)

	pe := ReleaseCheck{ID: "inicio", Title: "Sin programas nuevos que arranquen solos", Need: true, List: persist}
	switch {
	case len(persist) == 0:
		pe.OK, pe.Detail = true, "No hay entradas nuevas de inicio automático ni tareas programadas desde el ataque."
	case reviewed:
		pe.OK, pe.Detail = true, fmt.Sprintf("%d cambio(s) revisado(s) por el administrador.", len(persist))
	default:
		pe.Detail = fmt.Sprintf("%d cambio(s) desde el ataque: revísalos y márcalos como revisados.", len(persist))
	}
	out = append(out, pe)

	de := ReleaseCheck{ID: "senuelos", Title: "No ha vuelto a tocarse ningún documento trampa", Need: true, OK: newAttacks == 0}
	if newAttacks == 0 {
		de.Detail = "Desde la contención, ningún señuelo ha cambiado."
	} else {
		de.Detail = fmt.Sprintf("%d detección(es) nuevas durante la contención: algo sigue activo.", newAttacks)
	}
	out = append(out, de)
	return out
}

func CanRelease(l []ReleaseCheck) bool {
	for _, c := range l {
		if c.Need && !c.OK {
			return false
		}
	}
	return true
}
