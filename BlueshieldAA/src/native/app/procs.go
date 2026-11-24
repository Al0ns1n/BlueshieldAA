package main

// Procesos en marcha (Eventos → Procesos): clasificación portable, con tests.

import (
	"sort"
	"strings"
)

type ProcRow struct {
	PID     int     `json:"pid"`
	PPID    int     `json:"ppid"`
	Name    string  `json:"name"`
	Path    string  `json:"path"`
	Cmd     string  `json:"cmd"`
	User    string  `json:"user"`
	Company string  `json:"company"`
	Desc    string  `json:"desc"`
	CPU     float64 `json:"cpu"`
	Mem     int64   `json:"mem"`
	Start   string  `json:"start"`
	Signed  string  `json:"signed"` // "Microsoft", "Firmado", "Sin firmar", "Firma no válida", ""
	Signer  string  `json:"signer"`
	Conns   int     `json:"conns"`
	Flag    string  `json:"flag"` // "", "Revisar", "Alerta"
	Why     string  `json:"why"`
	Depth   int     `json:"depth"`
}

type ProcOut struct {
	Procs    []ProcRow `json:"procs"`
	Total    int       `json:"total"`
	Unsigned int       `json:"unsigned"`
	Flagged  int       `json:"flagged"`
	Net      int       `json:"net"`
}

var critical = map[string]bool{"system": true, "smss.exe": true, "csrss.exe": true, "wininit.exe": true, "winlogon.exe": true, "services.exe": true, "lsass.exe": true, "lsaiso.exe": true, "registry": true, "memory compression": true, "secure system": true, "fontdrvhost.exe": true, "dwm.exe": true, "svchost.exe": true}

func IsCritical(name string) bool { return critical[strings.ToLower(name)] }

// ClassifyProc marca los procesos que merece la pena mirar, sin alarmar por lo normal.
func ClassifyProc(p *ProcRow) {
	lp := strings.ToLower(p.Path)
	n := strings.ToLower(p.Name)
	base := strings.TrimSuffix(n, ".exe")
	userDir := hasAny(lp, `\appdata\local\temp\`, `\windows\temp\`, `\users\public\`, `\$recycle.bin\`, `\downloads\`, `\programdata\temp`)
	switch {
	case lp != "" && sysBins[base] && !strings.Contains(lp, `\windows\system32\`) && !strings.Contains(lp, `\windows\syswow64\`) && !strings.HasSuffix(lp, `\windows\explorer.exe`):
		p.Flag, p.Why = "Alerta", "Tiene el nombre de un componente de Windows pero no está en su carpeta: puede ser malware disfrazado."
	case userDir && p.Signed != "Microsoft" && p.Signed != "Firmado":
		p.Flag, p.Why = "Alerta", "Se ejecuta desde una carpeta temporal, Descargas o Público y no está firmado."
	case p.Signed == "Firma no válida":
		p.Flag, p.Why = "Alerta", "Su firma digital no es válida: el archivo puede haber sido modificado."
	case userDir:
		p.Flag, p.Why = "Revisar", "Se ejecuta desde una carpeta temporal o Descargas (aunque está firmado)."
	case p.Signed == "Sin firmar" && strings.Contains(lp, `\appdata\`) && p.Conns > 0:
		p.Flag, p.Why = "Revisar", "Programa sin firmar, instalado en la carpeta del usuario y conectado a la red."
	case (base == "powershell" || base == "pwsh" || base == "cmd" || base == "wscript" || base == "cscript" || base == "mshta") && hasAny(strings.ToLower(p.Cmd), "-enc", "-e ", "frombase64", "downloadstring", "hidden", "http://", "https://"):
		p.Flag, p.Why = "Alerta", "Consola o script con órdenes ocultas o que descargan de Internet."
	}
}

// ProcTree ordena la lista como árbol (padre → hijos) y pone la sangría.
func ProcTree(l []ProcRow) []ProcRow {
	by := map[int]int{}
	for i := range l {
		by[l[i].PID] = i
	}
	kids := map[int][]int{}
	var roots []int
	for i := range l {
		if j, ok := by[l[i].PPID]; ok && l[i].PPID != l[i].PID && l[i].PPID != 0 {
			kids[l[j].PID] = append(kids[l[j].PID], i)
		} else {
			roots = append(roots, i)
		}
	}
	name := func(i int) string { return strings.ToLower(l[i].Name) }
	sort.Slice(roots, func(a, b int) bool { return name(roots[a]) < name(roots[b]) })
	out := make([]ProcRow, 0, len(l))
	seen := map[int]bool{}
	var walk func(i, d int)
	walk = func(i, d int) {
		if seen[i] || d > 15 {
			return
		}
		seen[i] = true
		p := l[i]
		p.Depth = d
		out = append(out, p)
		k := kids[p.PID]
		sort.Slice(k, func(a, b int) bool { return name(k[a]) < name(k[b]) })
		for _, c := range k {
			walk(c, d+1)
		}
	}
	for _, r := range roots {
		walk(r, 0)
	}
	for i := range l {
		if !seen[i] {
			walk(i, 0)
		}
	}
	return out
}
