package main

// Motor de análisis de archivos BlueShieldAA 4.0 (portable, sin dependencias de Windows).
//
// Igual que el motor 2.0 de la 3.x: puntúa COMBINACIONES de comportamiento, nunca palabras
// sueltas. Solo cuenta texto que es código que se ejecuta (scripts, macros, accesos directos,
// HTA…); un documento o unos apuntes que "hablan" de malware no suben la puntuación.

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const FAEngineVersion = "4.0"
const faMaxRead = 64 << 20

type Finding struct {
	Level  string `json:"level"` // danger | warn | info | ok
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Points int    `json:"-"`
}

type FAResult struct {
	Err        string    `json:"err,omitempty"`
	Path       string    `json:"path"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Size       int64     `json:"size"`
	Partial    bool      `json:"partial"`
	SHA256     string    `json:"sha256"`
	SHA1       string    `json:"-"`
	MD5        string    `json:"-"`
	Score      int       `json:"score"`
	Verdict    string    `json:"verdict"`
	Findings   []Finding `json:"findings"`
	IOCs       []string  `json:"iocs"`
	Entries    []string  `json:"entries"`
	Origin     string    `json:"origin,omitempty"`
	Signature  string    `json:"signature,omitempty"`
	Signer     string    `json:"signer,omitempty"`
	Reputation string    `json:"reputation,omitempty"`
	KnownBad   bool      `json:"knownBad"`
	KnownGood  bool      `json:"knownGood"`
	Intel      []string  `json:"intel"`
	Defender   string    `json:"defender,omitempty"`
	Engine     string    `json:"engine"`
	Kind       string    `json:"-"` // pe, script, office, pdf, zip, lnk, text, image…
}

func (r *FAResult) add(level string, pts int, title, detail string) {
	r.Findings = append(r.Findings, Finding{Level: level, Title: title, Detail: detail, Points: pts})
}

// AnalyzeBytes hace el análisis estático. name sirve para la extensión.
func AnalyzeBytes(name string, data []byte, size int64) *FAResult {
	r := &FAResult{Name: filepath.Base(name), Size: size, Partial: size > int64(len(data)), Findings: []Finding{}, IOCs: []string{}, Entries: []string{}, Intel: []string{},
		Engine: "Motor BlueShieldAA " + FAEngineVersion}
	h := sha256.Sum256(data)
	r.SHA256 = hex.EncodeToString(h[:])
	h1 := sha1.Sum(data)
	r.SHA1 = hex.EncodeToString(h1[:])
	h5 := md5.Sum(data)
	r.MD5 = hex.EncodeToString(h5[:])

	if !RulesLoaded() {
		r.add("warn", 0, "Faltan las reglas del motor", "No se encuentra reglas-analisis.json junto al programa: solo se comprueban la huella, la firma y Defender. Reinstala BlueShieldAA.")
	}
	ext := strings.ToLower(filepath.Ext(name))
	r.Kind, r.Type = detectType(data, ext)

	// Extensión que no coincide con el contenido real
	if r.Kind == "pe" && ext != ".exe" && ext != ".dll" && ext != ".sys" && ext != ".scr" && ext != ".com" && ext != ".cpl" && ext != ".ocx" && ext != ".msi" && ext != ".efi" && ext != ".mui" && ext != ".node" && ext != ".pyd" {
		r.add("danger", 45, "Es un programa disfrazado", fmt.Sprintf("Por dentro es un programa de Windows, pero su extensión es «%s». Es un truco típico para que parezca un documento.", ext))
	}
	if doubleExt(r.Name) {
		r.add("danger", 35, "Doble extensión engañosa", "El nombre imita un documento («factura.pdf.exe» o similar) para ocultar que es ejecutable.")
	}
	if strings.ContainsRune(r.Name, '‮') {
		r.add("danger", 40, "Nombre con texto invertido", "Usa un carácter invisible (RLO) que da la vuelta al final del nombre para ocultar la extensión real.")
	}

	switch r.Kind {
	case "pe":
		analyzePE(r, data)
	case "script", "lnk", "hta":
		analyzeCode(r, stripComments(string(data), ext), r.Kind, ext)
	case "office-zip":
		analyzeOOXML(r, data)
	case "office-ole":
		analyzeOLE(r, data)
	case "pdf":
		analyzePDF(r, data)
	case "zip":
		analyzeZip(r, data)
	case "html":
		analyzeHTML(r, string(data))
	}
	r.IOCs = extractIOCs(data, 25)
	r.finish()
	return r
}

func (r *FAResult) finish() {
	s := 0
	for _, f := range r.Findings {
		s += f.Points
	}
	if r.KnownBad {
		s = max(s, 95)
	}
	if r.KnownGood && !r.KnownBad && s > 20 {
		s = 20
	}
	if s > 100 {
		s = 100
	}
	if s < 0 {
		s = 0
	}
	r.Score = s
	switch {
	case s >= 60:
		r.Verdict = "Peligroso"
	case s >= 25:
		r.Verdict = "Sospechoso"
	default:
		r.Verdict = "Sin señales de peligro"
	}
	sort.SliceStable(r.Findings, func(a, b int) bool { return levelRank(r.Findings[a].Level) < levelRank(r.Findings[b].Level) })
}

func levelRank(l string) int {
	return map[string]int{"danger": 0, "warn": 1, "info": 2, "ok": 3}[l]
}

var docExts = []string{".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".mp4", ".mp3", ".zip", ".rar", ".ppt", ".pptx", ".rtf"}
var exeExts = []string{".exe", ".scr", ".com", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".lnk", ".ps1", ".msi", ".pif", ".cpl"}

func doubleExt(name string) bool {
	n := strings.ToLower(name)
	for _, x := range exeExts {
		if !strings.HasSuffix(n, x) {
			continue
		}
		rest := strings.TrimSuffix(n, x)
		for _, d := range docExts {
			if strings.HasSuffix(strings.TrimRight(rest, " ."), d) {
				return true
			}
		}
	}
	return false
}

func detectType(b []byte, ext string) (kind, label string) {
	switch {
	case len(b) >= 2 && b[0] == 'M' && b[1] == 'Z':
		if isDLL(b) {
			return "pe", "Biblioteca de Windows (DLL)"
		}
		return "pe", "Programa de Windows (ejecutable)"
	case bytes.HasPrefix(b, []byte("%PDF")):
		return "pdf", "Documento PDF"
	case bytes.HasPrefix(b, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}):
		if ext == ".msi" {
			return "office-ole", "Instalador de Windows (MSI)"
		}
		return "office-ole", "Documento de Office antiguo (Word/Excel 97-2003)"
	case bytes.HasPrefix(b, []byte("PK\x03\x04")):
		if zipHas(b, "[Content_Types].xml") {
			return "office-zip", "Documento de Office (Word/Excel/PowerPoint)"
		}
		return "zip", "Archivo comprimido ZIP"
	case bytes.HasPrefix(b, []byte{0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0}):
		return "lnk", "Acceso directo de Windows (.lnk)"
	case bytes.HasPrefix(b, []byte("Rar!")):
		return "archive", "Archivo comprimido RAR"
	case bytes.HasPrefix(b, []byte("7z\xBC\xAF\x27\x1C")):
		return "archive", "Archivo comprimido 7-Zip"
	case bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF}):
		return "image", "Imagen JPEG"
	case bytes.HasPrefix(b, []byte("\x89PNG")):
		return "image", "Imagen PNG"
	case bytes.HasPrefix(b, []byte("{\\rtf")):
		return "rtf", "Documento RTF"
	}
	switch ext {
	case ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".py", ".sh":
		return "script", "Script (" + ext + ")"
	case ".hta":
		return "hta", "Aplicación HTML (.hta)"
	case ".html", ".htm", ".svg", ".shtml":
		return "html", "Página web (" + ext + ")"
	case ".iso", ".img", ".vhd", ".vhdx":
		return "archive", "Imagen de disco (" + ext + ")"
	}
	if isText(b) {
		return "text", "Texto"
	}
	return "data", "Datos (tipo no reconocido)"
}

func isText(b []byte) bool {
	n := len(b)
	if n > 4096 {
		n = 4096
	}
	bad := 0
	for _, c := range b[:n] {
		if c == 0 {
			return false
		}
		if c < 9 || (c > 13 && c < 32) {
			bad++
		}
	}
	return bad*20 < n+1
}

func isDLL(b []byte) bool {
	if len(b) < 0x40 {
		return false
	}
	off := int(b[0x3c]) | int(b[0x3d])<<8 | int(b[0x3e])<<16 | int(b[0x3f])<<24
	if off <= 0 || off+24 > len(b) || string(b[off:off+4]) != "PE\x00\x00" {
		return false
	}
	ch := int(b[off+22]) | int(b[off+23])<<8
	return ch&0x2000 != 0
}

func zipHas(b []byte, name string) bool {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return false
	}
	for _, f := range zr.File {
		if f.Name == name {
			return true
		}
	}
	return false
}

// ---------- programas (PE) ----------

func analyzePE(r *FAResult, b []byte) {
	s := strings.ToLower(asciiStrings(b, 5))
	// Combinaciones de capacidades (APIs importadas / cadenas) que solo tiene el malware
	inj := hasAllR(s, "pe_inyeccion_api") && hasAnyR(s, "pe_inyeccion_hilo")
	if inj {
		r.add("danger", 35, "Inyecta código en otros programas", "Tiene lo necesario para escribir y ejecutar código dentro de otros procesos, la técnica que usa el malware para esconderse.")
	}
	ransom := hasAnyR(s, "pe_borra_copias")
	if ransom {
		r.add("danger", 45, "Borra las copias de seguridad de Windows", "Contiene órdenes para eliminar las instantáneas y la recuperación de Windows: es lo primero que hace un ransomware.")
	}
	crypt := hasAnyR(s, "pe_cifra_api") && hasAnyR(s, "pe_cifra_busca")
	if crypt && (ransom || hasAnyR(s, "pe_rescate_texto")) {
		r.add("danger", 40, "Cifra archivos y pide rescate", "Recorre carpetas cifrando archivos y lleva un mensaje de rescate o referencias a pagos anónimos.")
	}
	keylog := hasAnyR(s, "pe_teclado_gancho") && hasAnyR(s, "pe_teclado_lee") && hasAnyR(s, "pe_teclado_envia")
	if keylog {
		r.add("danger", 35, "Registra el teclado y lo envía", "Captura lo que se teclea y tiene funciones para mandarlo fuera del equipo.")
	}
	stealer := countAnyR(s, "pe_robo_rutas") >= 3
	if stealer {
		r.add("danger", 40, "Busca contraseñas y monederos", "Apunta a las bases de contraseñas y cookies de varios navegadores o a monederos de criptomonedas: comportamiento de un ladrón de datos (stealer).")
	}
	avkill := hasAnyR(s, "pe_antivirus_off") && hasAnyR(s, "pe_antivirus_via")
	if avkill {
		r.add("danger", 30, "Intenta desactivar el antivirus", "Lleva órdenes para apagar Microsoft Defender o excluir carpetas de su análisis.")
	}
	persist := hasAnyR(s, "pe_persistencia")
	dl := hasAnyR(s, "pe_descarga")
	exe := hasAnyR(s, "pe_ejecuta")
	if dl && exe && persist {
		r.add("warn", 20, "Descarga, ejecuta y se instala al arrancar", "Combina descargar algo de Internet, ejecutarlo y quedarse en el inicio de Windows. Lo hacen los «droppers», aunque también algunos instaladores.")
	}
	if hasAnyR(s, "pe_upx") && !hasAnyR(s, "pe_upx_ms") {
		r.add("info", 5, "Comprimido con UPX", "Está empaquetado: no es malo en sí, pero el malware lo usa para que los antivirus no vean su contenido.")
	}
	if entropy(b) > 7.6 && len(b) > 50000 {
		r.add("info", 8, "Contenido muy cifrado u ofuscado", "Casi todo su contenido parece aleatorio: suele indicar que está empaquetado u ofuscado.")
	}
}

// ---------- scripts, accesos directos, HTA ----------

var reB64 = regexp.MustCompile(`[A-Za-z0-9+/]{120,}={0,2}`)

func analyzeCode(r *FAResult, src string, kind string, ext string) {
	s := strings.ToLower(src)
	// .js / .ts / .py…: con doble clic en Windows solo un .js/.jse puede tocar el sistema, y solo
	// a través de Windows Script Host (WScript, ActiveXObject…). Código "normal" no puntúa.
	switch ext {
	case ".js", ".jse", ".mjs", ".cjs", ".ts":
		if !hasAnyR(s, "js_wsh") {
			r.add("ok", 0, "JavaScript sin acceso al sistema", "Es código JavaScript corriente (web, Node.js, ejercicios…). No usa Windows Script Host, así que al abrirlo con doble clic no puede descargar ni ejecutar nada en el equipo.")
			return
		}
	case ".py", ".sh", ".rb", ".pl", ".php":
		r.add("info", 0, "Código fuente", "Es código de programación. Windows no lo ejecuta al hacer doble clic salvo que tengas ese lenguaje instalado; se revisa igualmente pero con menos peso.")
		defer func() {
			for i := range r.Findings {
				if r.Findings[i].Points > 0 {
					r.Findings[i].Points /= 3
					if r.Findings[i].Level == "danger" {
						r.Findings[i].Level = "warn"
					}
				}
			}
		}()
	}
	if kind == "lnk" {
		s = strings.ToLower(asciiStrings([]byte(src), 4) + " " + utf16Strings([]byte(src)))
		if hasAnyR(s, "lnk_lanza") {
			r.add("danger", 45, "El acceso directo ejecuta órdenes", "En vez de abrir un documento, lanza PowerShell, la consola u otra herramienta de Windows. Es un método muy usado en correos maliciosos.")
		}
	}
	download := hasAnyR(s, "sc_descarga")
	execute := hasAnyR(s, "sc_ejecuta")
	hidden := hasAnyR(s, "sc_oculto")
	obf := reB64.MatchString(src) && hasAnyR(s, "sc_codificado")
	obf = obf || strings.Count(s, "[char]") > 8 || strings.Count(s, "chr(") > 15 || strings.Count(s, "string.fromcharcode") > 2
	persist := hasAnyR(s, "sc_persistencia")
	avkill := hasAnyR(s, "sc_antivirus_off")
	shadows := hasAnyR(s, "sc_borra_copias")
	cred := hasAnyR(s, "sc_credenciales")
	lolbin := hasAnyR(s, "sc_lolbin")

	if download && execute {
		pts, lvl := 30, "warn"
		if hidden || obf {
			pts, lvl = 60, "danger"
		}
		r.add(lvl, pts, "Descarga algo de Internet y lo ejecuta", "Combina bajar un archivo o código de Internet con ejecutarlo"+ternary(hidden, " sin mostrar ninguna ventana", "")+". Es el comportamiento de un «descargador» de malware.")
	}
	if obf && execute {
		r.add("danger", 30, "Código ocultado que se ejecuta", "Trae código codificado (Base64, caracteres sueltos…) y lo ejecuta, para que no se vea qué hace.")
	}
	if avkill {
		r.add("danger", 40, "Intenta desactivar la protección", "Apaga Microsoft Defender, añade exclusiones o desactiva AMSI, el sistema que deja a los antivirus revisar scripts.")
	}
	if shadows {
		r.add("danger", 45, "Borra las copias de seguridad de Windows", "Elimina las instantáneas o la recuperación de Windows: típico de un ransomware antes de cifrar.")
	}
	if cred {
		r.add("danger", 45, "Roba credenciales de Windows", "Intenta volcar la memoria de LSASS o la base SAM, donde Windows guarda las contraseñas.")
	}
	if persist && (download || obf || hidden) {
		r.add("danger", 25, "Se instala para arrancar con Windows", "Además de lo anterior, se queda en el inicio o en una tarea programada para volver a ejecutarse.")
	} else if persist {
		r.add("info", 5, "Se configura para arrancar con Windows", "Crea una entrada de inicio, tarea o servicio. Es normal en scripts de administración.")
	}
	if lolbin && (download || execute) {
		r.add("warn", 15, "Usa herramientas de Windows para colar código", "Recurre a certutil, bitsadmin, mshta o regsvr32 de forma poco habitual: los atacantes lo usan para saltarse el antivirus.")
	}
	if hidden && !download && !obf && execute {
		r.add("info", 5, "Se ejecuta sin ventana", "Lanza programas ocultos. Habitual también en scripts de administración.")
	}
	if kind == "hta" && (execute || download) {
		r.add("warn", 15, "Aplicación HTML con código", "Los archivos .hta se ejecutan con todos los permisos del usuario, sin las protecciones del navegador.")
	}
	if len(r.Findings) == 0 && kind == "script" {
		r.add("ok", 0, "Script sin combinaciones peligrosas", "Es código ejecutable, pero no combina descargar, ocultarse, desactivar protecciones o robar datos.")
	}
}

// ---------- Office ----------

func analyzeOOXML(r *FAResult, b []byte) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return
	}
	macros := false
	for _, f := range zr.File {
		n := strings.ToLower(f.Name)
		r.Entries = append(r.Entries, f.Name)
		if strings.HasSuffix(n, "vbaproject.bin") {
			macros = true
			if rc, err := f.Open(); err == nil {
				data, _ := io.ReadAll(io.LimitReader(rc, 8<<20))
				rc.Close()
				macroCheck(r, data)
			}
		}
		if strings.HasSuffix(n, ".rels") {
			if rc, err := f.Open(); err == nil {
				data, _ := io.ReadAll(io.LimitReader(rc, 1<<20))
				rc.Close()
				ls := strings.ToLower(string(data))
				if strings.Contains(ls, "targetmode=\"external\"") && (strings.Contains(ls, "attachedtemplate") || strings.Contains(ls, "oleobject")) && strings.Contains(ls, "http") {
					r.add("danger", 40, "Descarga una plantilla o un objeto remoto", "Al abrirlo, el documento pide contenido a una dirección de Internet. Es una técnica para colar macros o explotar fallos de Office.")
				}
			}
		}
		if strings.Contains(n, "activex") || strings.Contains(n, "embeddings/oleobject") {
			r.add("info", 5, "Lleva objetos incrustados", "Tiene controles ActiveX u objetos OLE dentro. Pueden ser legítimos.")
		}
	}
	if macros {
		r.add("warn", 10, "Tiene macros", "Incluye código VBA. Office lo bloquea si viene de Internet; no lo actives si no esperabas un documento con macros.")
	}
}

func analyzeOLE(r *FAResult, b []byte) {
	if bytes.Contains(b, []byte("_VBA_PROJECT")) || bytes.Contains(b, []byte("VBA")) && bytes.Contains(b, []byte("Attribut")) {
		r.add("warn", 10, "Tiene macros", "Incluye código VBA. No lo actives si no esperabas un documento con macros.")
		macroCheck(r, b)
	}
	if bytes.Contains(bytes.ToLower(b), []byte("equation.3")) {
		r.add("danger", 35, "Objeto del Editor de ecuaciones", "Lleva un objeto «Equation.3», muy usado para explotar un fallo antiguo de Office (CVE-2017-11882).")
	}
}

func macroCheck(r *FAResult, b []byte) {
	s := strings.ToLower(asciiStrings(b, 4))
	auto := hasAnyR(s, "macro_auto")
	run := hasAnyR(s, "macro_ejecuta")
	net := hasAnyR(s, "macro_red")
	if auto && run && net {
		r.add("danger", 55, "Macro que descarga y ejecuta al abrir", "La macro arranca sola al abrir el documento, baja algo de Internet y lo ejecuta. Es el clásico documento-trampa de los correos de phishing.")
	} else if auto && run {
		r.add("danger", 35, "Macro que ejecuta programas al abrir", "La macro se lanza sola al abrir y ejecuta programas u órdenes del sistema.")
	} else if run && net {
		r.add("warn", 20, "Macro con conexión a Internet y ejecución", "Puede descargar y ejecutar cosas, aunque no se lanza sola al abrir.")
	}
}

// ---------- PDF ----------

func analyzePDF(r *FAResult, b []byte) {
	s := string(b)
	// el JavaScript de un PDF suele ir comprimido: se descomprimen los flujos para leerlo
	code := strings.ToLower(s + "\n" + pdfStreams(b, 8<<20))
	js := strings.Contains(s, "/JavaScript") || strings.Contains(s, "/JS")
	launch := strings.Contains(s, "/Launch")
	embed := strings.Contains(s, "/EmbeddedFile")
	if launch {
		r.add("danger", 40, "Intenta ejecutar un programa", "Contiene una acción /Launch para abrir programas o archivos del equipo.")
	}
	danger := []string{}
	for _, k := range rule("pdf_js_peligroso") {
		if strings.Contains(code, k) {
			danger = append(danger, k)
		}
	}
	spray := strings.Contains(code, "unescape(") && strings.Count(code, "%u") > 20
	switch {
	case js && (len(danger) > 0 || spray):
		pts := 25 + 10*len(danger)
		if spray {
			pts += 30
		}
		r.add(ternary(pts >= 45, "danger", "warn"), pts, "JavaScript con funciones peligrosas", "El código del PDF usa funciones que sirven para atacar: "+strings.Join(firstN(danger, 5), ", ")+ternary(spray, " y prepara memoria como hacen los exploits", "")+".")
	case js && hasAnyR(code, "pdf_js_formulario"):
		r.add("ok", 0, "JavaScript de formulario", "El PDF trae código para validar o calcular campos de un formulario. Es normal y no puede tocar el equipo.")
	case js:
		r.add("info", 0, "Lleva JavaScript", "Tiene algo de código, pero no usa ninguna función que permita atacar el equipo.")
	}
	if embed {
		names := pdfEmbeddedNames(s)
		bad := false
		for _, n := range names {
			for _, x := range exeExts {
				if strings.HasSuffix(strings.ToLower(n), x) {
					bad = true
				}
			}
		}
		if bad {
			r.add("danger", 35, "Esconde un programa dentro del PDF", "Lleva incrustado un ejecutable o script: "+strings.Join(firstN(names, 4), ", ")+".")
		} else {
			r.add("info", 0, "Lleva archivos adjuntos", "El PDF contiene otros archivos dentro"+ternary(len(names) > 0, ": "+strings.Join(firstN(names, 4), ", "), "")+".")
		}
	}
}

// ---------- ZIP ----------

func analyzeZip(r *FAResult, b []byte) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		r.add("info", 0, "No se pudo abrir el comprimido", "Puede estar dañado o protegido con contraseña.")
		return
	}
	enc, exes := false, []string{}
	for _, f := range zr.File {
		r.Entries = append(r.Entries, f.Name)
		if f.Flags&1 == 1 {
			enc = true
		}
		n := strings.ToLower(f.Name)
		for _, x := range exeExts {
			if strings.HasSuffix(n, x) {
				exes = append(exes, f.Name)
				break
			}
		}
		if doubleExt(filepath.Base(f.Name)) {
			r.add("danger", 35, "Dentro hay un archivo con doble extensión", "«"+f.Name+"» se hace pasar por un documento.")
		}
		// se analiza por dentro lo pequeño y ejecutable
		if len(exes) > 0 && exes[len(exes)-1] == f.Name && f.UncompressedSize64 < 4<<20 && f.Flags&1 == 0 {
			if rc, err := f.Open(); err == nil {
				data, _ := io.ReadAll(io.LimitReader(rc, 4<<20))
				rc.Close()
				sub := AnalyzeBytes(f.Name, data, int64(len(data)))
				for _, fd := range sub.Findings {
					if fd.Points >= 20 {
						fd.Title = fd.Title + " (en " + filepath.Base(f.Name) + ")"
						r.Findings = append(r.Findings, fd)
					}
				}
			}
		}
	}
	if len(exes) > 0 && enc {
		r.add("danger", 35, "Comprimido con contraseña que esconde un ejecutable", "Proteger con contraseña un .zip con programas o scripts dentro sirve para que el antivirus del correo no pueda revisarlo.")
	} else if len(exes) > 0 {
		r.add("warn", 10, "Contiene programas o scripts", strings.Join(firstN(exes, 5), ", "))
	}
}

func analyzeHTML(r *FAResult, src string) {
	s := strings.ToLower(src)
	if hasAnyR(s, "html_password") && hasAnyR(s, "html_marcas") && hasAnyR(s, "html_envio") {
		r.add("danger", 45, "Formulario falso de inicio de sesión", "Es una página que pide contraseña imitando a Microsoft, un banco u otro servicio, y la envía a otro sitio. Típico adjunto de phishing.")
	}
	if strings.Contains(s, "atob(") && hasAnyR(s, "html_redirige") {
		r.add("info", 5, "Código que descodifica contenido", "Descodifica texto oculto para mostrarlo o redirigir. Lo usan algunas páginas trampa, pero también muchas páginas normales.")
	}
	if hasAnyR(s, "html_descarga") && hasAnyR(s, "html_tipos") && strings.Contains(s, "atob(") {
		r.add("danger", 35, "Fabrica y descarga un archivo al abrirse", "La página reconstruye un archivo escondido y lo descarga (HTML smuggling).")
	}
}

// ---------- utilidades ----------

var reURL = regexp.MustCompile(`(?i)\bhttps?://[a-z0-9][a-z0-9.\-]{2,253}(?::\d{2,5})?(?:/[^\s"'<>\x00]{0,120})?`)
var reIP = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)

var benignHosts = []string{"schemas.microsoft.com", "schemas.openxmlformats.org", "www.w3.org", "purl.org", "ns.adobe.com", "crl.microsoft.com", "www.microsoft.com/pki", "ocsp.", "crl3.digicert.com", "crl4.digicert.com", "digicert.com", "verisign.com", "symantec.com", "globalsign", "sectigo.com", "usertrust.com", "comodoca.com", "xml.org", "apache.org/xml", "openoffice.org", "iptc.org", "example.com"}

func extractIOCs(b []byte, n int) []string {
	text := asciiStrings(b, 6) + "\n" + utf16Strings(b)
	seen := map[string]bool{}
	out := []string{}
	for _, u := range reURL.FindAllString(text, -1) {
		u = strings.TrimRight(u, ".,);]'\"")
		lu := strings.ToLower(u)
		skip := false
		for _, h := range benignHosts {
			if strings.Contains(lu, h) {
				skip = true
				break
			}
		}
		if skip || seen[lu] {
			continue
		}
		seen[lu] = true
		out = append(out, u)
		if len(out) >= n {
			return out
		}
	}
	for _, ip := range reIP.FindAllString(text, -1) {
		if seen[ip] || strings.HasPrefix(ip, "0.") || strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "255.") || strings.Count(ip, ".0") >= 2 {
			continue
		}
		// descarta números de versión tipo 1.2.3.4
		if strings.HasPrefix(ip, "1.") || strings.HasPrefix(ip, "2.") || strings.HasPrefix(ip, "4.") || strings.HasPrefix(ip, "5.") || strings.HasPrefix(ip, "6.") {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
		if len(out) >= n {
			break
		}
	}
	return out
}

func asciiStrings(b []byte, min int) string {
	var sb strings.Builder
	start := -1
	for i, c := range b {
		if c >= 32 && c < 127 || c == '\t' {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= min {
			sb.Write(b[start:i])
			sb.WriteByte('\n')
		}
		start = -1
	}
	if start >= 0 && len(b)-start >= min {
		sb.Write(b[start:])
	}
	return sb.String()
}

func utf16Strings(b []byte) string {
	var sb strings.Builder
	run := []byte{}
	for i := 0; i+1 < len(b); i += 2 {
		if b[i+1] == 0 && b[i] >= 32 && b[i] < 127 {
			run = append(run, b[i])
			continue
		}
		if len(run) >= 5 {
			sb.Write(run)
			sb.WriteByte('\n')
		}
		run = run[:0]
	}
	if len(run) >= 5 {
		sb.Write(run)
	}
	return sb.String()
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var f [256]float64
	for _, c := range b {
		f[c]++
	}
	n := float64(len(b))
	e := 0.0
	for _, v := range f {
		if v > 0 {
			p := v / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

func hasAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func hasAll(s string, subs ...string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}

func countAny(s string, subs ...string) int {
	n := 0
	for _, x := range subs {
		if strings.Contains(s, x) {
			n++
		}
	}
	return n
}

func firstN(l []string, n int) []string {
	if len(l) > n {
		return l[:n]
	}
	return l
}

func ternary[T any](c bool, a, b T) T {
	if c {
		return a
	}
	return b
}

// ReadForAnalysis lee como mucho 64 MB del archivo.
func ReadForAnalysis(path string) ([]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	if st.IsDir() {
		return nil, 0, fmt.Errorf("es una carpeta, no un archivo")
	}
	b, err := io.ReadAll(io.LimitReader(f, faMaxRead))
	return b, st.Size(), err
}

var reFlate = regexp.MustCompile(`(?s)/FlateDecode.{0,300}?stream\r?\n`)
var reEmbName = regexp.MustCompile(`/F(?:ileName)?\s*\(([^)]{1,120}\.[A-Za-z0-9]{1,5})\)`)

// pdfStreams descomprime los flujos FlateDecode (hasta max bytes en total).
func pdfStreams(b []byte, max int) string {
	var sb strings.Builder
	for _, loc := range reFlate.FindAllIndex(b, 400) {
		start := loc[1]
		end := bytes.Index(b[start:], []byte("endstream"))
		if end < 0 {
			continue
		}
		zr, err := zlib.NewReader(bytes.NewReader(b[start : start+end]))
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(zr, 2<<20))
		zr.Close()
		if isText(data) {
			sb.Write(data)
			sb.WriteByte('\n')
		}
		if sb.Len() > max {
			break
		}
	}
	return sb.String()
}

func pdfEmbeddedNames(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range reEmbName.FindAllStringSubmatch(s, 20) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// stripComments quita los comentarios del código para que lo que se "comenta" no cuente.
func stripComments(src, ext string) string {
	var reBlock, reLine *regexp.Regexp
	switch ext {
	case ".ps1", ".psm1":
		reBlock, reLine = regexp.MustCompile(`(?s)<#.*?#>`), regexp.MustCompile(`(?m)^\s*#.*$`)
	case ".js", ".jse", ".mjs", ".cjs", ".ts":
		reBlock, reLine = regexp.MustCompile(`(?s)/\*.*?\*/`), regexp.MustCompile(`(?m)^\s*//.*$`)
	case ".vbs", ".vbe":
		reLine = regexp.MustCompile(`(?mi)^\s*('|rem\s).*$`)
	case ".bat", ".cmd":
		reLine = regexp.MustCompile(`(?mi)^\s*(rem(\s|$)|::).*$`)
	case ".py", ".sh", ".rb", ".pl":
		reLine = regexp.MustCompile(`(?m)^\s*#.*$`)
	}
	if reBlock != nil {
		src = reBlock.ReplaceAllString(src, "")
	}
	if reLine != nil {
		src = reLine.ReplaceAllString(src, "")
	}
	return src
}
