package main

// Análisis dinámico en Windows Sandbox: interpretación del informe (portable, con tests).

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

type SBProc struct {
	PID  int     `json:"pid"`
	PPID int     `json:"ppid"`
	Name string  `json:"name"`
	Cmd  string  `json:"cmd"`
	Path string  `json:"path"`
	T    float64 `json:"t"`
	// rellenado por BuildDynamic
	Depth int    `json:"depth"`
	Flag  string `json:"flag"` // "", "esperado", "ruido", "sospechoso", "peligroso"
	Why   string `json:"why,omitempty"`
}

type SBFile struct {
	P    string `json:"p"`
	S    int64  `json:"s"`
	Flag string `json:"flag,omitempty"`
}

type SBReport struct {
	Name    string   `json:"name"`
	Seconds int      `json:"seconds"`
	Opened  bool     `json:"opened"`
	OpenErr string   `json:"openErr"`
	Procs   []SBProc `json:"procs"`
	Files   []SBFile `json:"files"`
	RunNew  []struct {
		K string `json:"k"`
		V string `json:"v"`
	} `json:"runNew"`
	TasksNew      []string `json:"tasksNew"`
	SvcNew        []string `json:"svcNew"`
	Startup       []string `json:"startup"`
	DecoysChanged int      `json:"decoysChanged"`
	DecoysDeleted int      `json:"decoysDeleted"`
	DecoysTotal   int      `json:"decoysTotal"`
	NewInDocs     []string `json:"newInDocs"`
	Defender      []string `json:"defender"`
	Shots         int      `json:"shots"`
}

// SBResult: lo que ve la interfaz.
type SBResult struct {
	Verdict  string    `json:"verdict"` // "Limpio", "Sospechoso", "Peligroso", "No concluyente"
	Summary  string    `json:"summary"`
	Findings []Finding `json:"findings"`
	Procs    []SBProc  `json:"procs"` // árbol ya ordenado (Depth = sangría)
	Files    []SBFile  `json:"files"`
	Persist  []string  `json:"persist"`
	Decoys   string    `json:"decoys"`
	Viewer   string    `json:"viewer"`
}

func ParseSBReport(b []byte) (SBReport, error) {
	var r SBReport
	b = []byte(strings.TrimPrefix(string(b), "\ufeff"))
	err := json.Unmarshal(b, &r)
	return r, err
}

// visores esperables al abrir cada tipo de archivo en un Windows limpio
func expectedViewers(ext string) []string {
	switch ext {
	case ".pdf", ".htm", ".html", ".svg", ".xml", ".mht":
		return []string{"msedge.exe"}
	case ".txt", ".log", ".csv", ".ps1", ".psm1", ".py", ".ini", ".json", ".md":
		return []string{"notepad.exe"}
	case ".js", ".jse", ".vbs", ".vbe", ".wsf":
		return []string{"wscript.exe"}
	case ".hta":
		return []string{"mshta.exe"}
	case ".bat", ".cmd":
		return []string{"cmd.exe"}
	case ".msi":
		return []string{"msiexec.exe"}
	case ".zip", ".iso", ".img", ".vhd":
		return []string{"explorer.exe"}
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp":
		return []string{"photos.exe", "microsoft.photos.exe", "mspaint.exe"}
	}
	return nil
}

func inList(name, key string) bool {
	n := strings.ToLower(name)
	for _, x := range rule(key) {
		if n == x {
			return true
		}
	}
	return false
}

// BuildDynamic convierte el informe del entorno aislado en hallazgos y un veredicto.
func BuildDynamic(rep SBReport, kind string) SBResult {
	res := SBResult{Findings: []Finding{}}
	ext := strings.ToLower(filepath.Ext(rep.Name))
	sample := strings.ToLower(rep.Name)
	expected := expectedViewers(ext)
	add := func(level string, pts int, title, detail string) {
		res.Findings = append(res.Findings, Finding{Level: level, Points: pts, Title: title, Detail: detail})
	}

	// --- procesos ---
	byPID := map[int]*SBProc{}
	for i := range rep.Procs {
		byPID[rep.Procs[i].PID] = &rep.Procs[i]
	}
	isExpected := func(n string) bool {
		n = strings.ToLower(n)
		if n == sample {
			return true
		}
		for _, x := range expected {
			if n == x {
				return true
			}
		}
		return false
	}
	viewerSeen := ""
	susp, bad := 0, 0
	var cmdText []string
	for i := range rep.Procs {
		p := &rep.Procs[i]
		name := strings.ToLower(p.Name)
		lp := strings.ToLower(p.Path)
		switch {
		case isExpected(name):
			p.Flag = "esperado"
			if viewerSeen == "" {
				viewerSeen = p.Name
			}
		case inList(name, "sandbox_lolbins"):
			p.Flag, p.Why = "sospechoso", "Herramienta de Windows que el malware usa para ejecutar órdenes"
			susp++
			cmdText = append(cmdText, p.Cmd)
		case lp != "" && hasAny(lp, `\appdata\`, `\temp\`, `\users\public\`, `\programdata\`) && !hasAnyR(lp, "sandbox_ruta_ruido"):
			p.Flag, p.Why = "peligroso", "Programa que acaba de aparecer en una carpeta de usuario o temporal y se ha ejecutado"
			bad++
		case inList(name, "sandbox_ruido"):
			p.Flag = "ruido"
		default:
			if ext == ".exe" || ext == ".msi" || ext == ".lnk" || ext == ".scr" {
				p.Flag = "esperado" // un instalador lanza sus propios procesos
			} else {
				p.Flag, p.Why = "sospechoso", "Proceso que no es normal al abrir este tipo de archivo"
				susp++
			}
		}
	}
	// la cmd que acompaña a un .bat es lo esperado, pero lo que lanza no
	if len(cmdText) > 0 {
		tmp := &FAResult{Findings: []Finding{}}
		analyzeCode(tmp, strings.Join(cmdText, "\n"), "script", ".cmd")
		for _, f := range tmp.Findings {
			if f.Points >= 20 {
				add(f.Level, f.Points, f.Title+" (visto en el entorno aislado)", f.Detail)
			}
		}
	}
	if bad > 0 {
		add("danger", 60, "Crea y ejecuta programas nuevos", fmt.Sprintf("Durante la prueba se ejecutaron %d programa(s) que acababan de aparecer en carpetas de usuario o temporales. Es lo que hace un «dropper».", bad))
	}
	if susp > 0 {
		add(ternary(susp >= 2, "danger", "warn"), ternary(susp >= 2, 45, 25), "Lanza herramientas de Windows", fmt.Sprintf("Al abrirlo se ejecutaron %d proceso(s) que un documento normal no necesita (consola, PowerShell, scripts…). Mira el árbol de procesos.", susp))
	}

	// --- archivos ---
	exeNew := 0
	for _, f := range rep.Files {
		lp := strings.ToLower(f.P)
		if hasAnyR(lp, "sandbox_ruta_ruido") {
			continue
		}
		fl := ""
		for _, x := range exeExts {
			if strings.HasSuffix(lp, x) || strings.HasSuffix(lp, ".dll") {
				fl = "ejecutable"
				exeNew++
				break
			}
		}
		res.Files = append(res.Files, SBFile{P: f.P, S: f.S, Flag: fl})
	}
	if exeNew > 0 {
		add("danger", 40, "Deja programas o scripts en el equipo", fmt.Sprintf("Ha creado %d archivo(s) ejecutable(s) (.exe, .dll, scripts…). Un documento normal no hace esto.", exeNew))
	}

	// --- persistencia ---
	for _, r := range rep.RunNew {
		res.Persist = append(res.Persist, "Inicio automático: "+r.K+" = "+r.V)
	}
	for _, t := range rep.TasksNew {
		res.Persist = append(res.Persist, "Tarea programada: "+t)
	}
	for _, s := range rep.SvcNew {
		res.Persist = append(res.Persist, "Servicio: "+s)
	}
	for _, s := range rep.Startup {
		res.Persist = append(res.Persist, "Carpeta de inicio: "+s)
	}
	if len(res.Persist) > 0 && ext != ".msi" && ext != ".exe" {
		add("danger", 50, "Se instala para arrancar con Windows", "Ha creado una entrada de inicio automático, una tarea programada o un servicio para volver a ejecutarse.")
	} else if len(res.Persist) > 0 {
		add("info", 5, "Deja algo que arranca con Windows", "Es normal en un instalador; comprueba que es del programa que esperas.")
	}

	// --- señuelos (ransomware) ---
	touched := rep.DecoysChanged + rep.DecoysDeleted
	if rep.DecoysTotal > 0 {
		res.Decoys = fmt.Sprintf("%d de %d documentos de prueba modificados o borrados", touched, rep.DecoysTotal)
	}
	if touched >= 3 {
		add("danger", 95, "Cifra o destruye documentos (ransomware)", fmt.Sprintf("De %d documentos de prueba que había en Documentos e Imágenes, %d se han modificado y %d se han borrado.", rep.DecoysTotal, rep.DecoysChanged, rep.DecoysDeleted))
	} else if touched > 0 {
		add("warn", 25, "Toca documentos del usuario", fmt.Sprintf("Ha modificado o borrado %d documento(s) de prueba.", touched))
	}
	for _, n := range rep.NewInDocs {
		if hasAny(strings.ToLower(n), "readme", "decrypt", "recover", "restore", "how_to", "rescate", ".hta") {
			add("danger", 60, "Deja una nota de rescate", "Ha creado «"+n+"» junto a los documentos.")
			break
		}
	}
	for _, d := range rep.Defender {
		add("danger", 70, "Microsoft Defender lo ha detenido en el entorno aislado", d)
	}

	// --- árbol de procesos (ordenado por padre) ---
	children := map[int][]*SBProc{}
	var roots []*SBProc
	for i := range rep.Procs {
		p := &rep.Procs[i]
		if _, ok := byPID[p.PPID]; ok && p.PPID != p.PID {
			children[p.PPID] = append(children[p.PPID], p)
		} else {
			roots = append(roots, p)
		}
	}
	var walk func(p *SBProc, d int)
	seen := map[int]bool{}
	walk = func(p *SBProc, d int) {
		if seen[p.PID] || d > 12 {
			return
		}
		seen[p.PID] = true
		p.Depth = d
		res.Procs = append(res.Procs, *p)
		kids := children[p.PID]
		sort.Slice(kids, func(a, b int) bool { return kids[a].T < kids[b].T })
		for _, k := range kids {
			walk(k, d+1)
		}
	}
	sort.Slice(roots, func(a, b int) bool { return roots[a].T < roots[b].T })
	for _, r := range roots {
		walk(r, 0)
	}
	// sin ruido de Windows en el árbol, salvo que tenga hijos interesantes
	clean := res.Procs[:0]
	for _, p := range res.Procs {
		if p.Flag != "ruido" {
			clean = append(clean, p)
		}
	}
	res.Procs = clean
	res.Viewer = viewerSeen

	// --- veredicto ---
	score := 0
	for _, f := range res.Findings {
		score += f.Points
	}
	switch {
	case score >= 60:
		res.Verdict = "Peligroso"
		res.Summary = "En el entorno aislado ha hecho cosas propias de malware."
	case score >= 25:
		res.Verdict = "Sospechoso"
		res.Summary = "En el entorno aislado ha hecho algo poco habitual. Revisa el detalle."
	case !rep.Opened || (viewerSeen == "" && len(expected) > 0):
		res.Verdict = "No concluyente"
		res.Summary = "No se ha podido abrir de forma normal en el entorno aislado" + ternary(rep.OpenErr != "", " ("+sbFirstLine(rep.OpenErr)+")", "") + ternary(kind == "office-zip" || kind == "office-ole", ". Windows Sandbox no trae Office, así que las macros no se pueden ejecutar allí.", ".")
	default:
		res.Verdict = "Limpio"
		res.Summary = fmt.Sprintf("Se abrió%s y durante %d s no hizo nada sospechoso: no lanzó otros programas, no dejó ejecutables, no se instaló para arrancar con Windows y no tocó los documentos de prueba.", ternary(viewerSeen != "", " con "+viewerSeen, ""), rep.Seconds)
		add("ok", 0, "Sin comportamiento malicioso", res.Summary)
	}
	sort.SliceStable(res.Findings, func(a, b int) bool { return levelRank(res.Findings[a].Level) < levelRank(res.Findings[b].Level) })
	return res
}

func sbFirstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i > 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// CombineVerdict junta el análisis estático y el dinámico (el dinámico es la prueba real).
func CombineVerdict(r *FAResult, d SBResult) {
	staticDanger := false
	for _, f := range r.Findings {
		if f.Level == "danger" && f.Points >= 30 {
			staticDanger = true
		}
	}
	for _, f := range d.Findings {
		if f.Points > 0 {
			f.Title = "Entorno aislado: " + f.Title
			r.Findings = append(r.Findings, f)
		}
	}
	switch d.Verdict {
	case "Limpio":
		r.add("ok", 0, "Probado en el entorno aislado: sin comportamiento malicioso", d.Summary)
		if !staticDanger && !r.KnownBad {
			// lo estático solo eran indicios (JavaScript, macros…) y la prueba real no muestra nada
			r.finish()
			if r.Score > 15 {
				r.Score = 15
			}
			r.Verdict = "Sin señales de peligro"
			return
		}
	}
	r.finish()
}
