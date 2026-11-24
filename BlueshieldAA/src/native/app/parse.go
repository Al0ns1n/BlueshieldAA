package main

// Lectores de la salida de herramientas de Windows (winget, PowerShell). Sin dependencias de
// Windows para poder probarlos con "go test" desde Linux.

import (
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"
)

type WingetPkg struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	Version   string `json:"version"`
	Available string `json:"available"`
	Source    string `json:"source"`
}

// cleanConsole quita el "spinner" y los retornos de carro que winget mezcla con la salida.
func cleanConsole(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if i := strings.LastIndex(ln, "\r"); i >= 0 {
			ln = ln[i+1:]
		}
		t := strings.TrimSpace(ln)
		if t == "-" || t == "\\" || t == "|" || t == "/" {
			continue
		}
		// barras de progreso de descarga
		if strings.ContainsAny(t, "█▒") {
			continue
		}
		out = append(out, strings.TrimRight(ln, " \t"))
	}
	return strings.Join(out, "\n")
}

var dashLine = regexp.MustCompile(`^-{10,}\s*$`)

// ParseWingetTable lee la tabla de "winget upgrade" / "winget list" (en cualquier idioma).
// Las columnas se sacan de la posición de cada palabra de la cabecera.
func ParseWingetTable(raw string) []WingetPkg {
	lines := strings.Split(cleanConsole(raw), "\n")
	var res []WingetPkg
	for i := 1; i < len(lines); i++ {
		if !dashLine.MatchString(strings.TrimSpace(lines[i])) {
			continue
		}
		head := []rune(lines[i-1])
		// la cabecera puede llevar restos del spinner delante
		var starts []int
		for k := 0; k < len(head); k++ {
			if head[k] != ' ' && (k == 0 || head[k-1] == ' ') {
				starts = append(starts, k)
			}
		}
		if len(starts) < 3 {
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			ln := lines[j]
			if strings.TrimSpace(ln) == "" {
				break
			}
			r := []rune(ln)
			cols := make([]string, len(starts))
			for c := range starts {
				a := starts[c]
				b := len(r)
				if c+1 < len(starts) {
					b = starts[c+1]
				}
				if a > len(r) {
					a = len(r)
				}
				if b > len(r) {
					b = len(r)
				}
				cols[c] = strings.TrimSpace(string(r[a:b]))
			}
			bad := len(cols) < 3 || cols[1] == ""
			for c := 1; c < len(cols) && !bad; c++ {
				a := starts[c]
				if strings.Contains(cols[c], " ") || (a > 0 && a < len(r) && r[a-1] != ' ' && r[a] != ' ') {
					bad = true
				}
			}
			if bad {
				// fila mal alineada (nombres con caracteres anchos): se reparte por espacios
				cols = splitFallback(ln, len(starts))
				if cols == nil {
					continue
				}
			}
			p := WingetPkg{Name: cols[0], ID: cols[1], Version: cols[2]}
			if len(cols) >= 5 {
				p.Available, p.Source = cols[3], cols[4]
			} else if len(cols) == 4 {
				// "winget list" sin columna Disponible, o "upgrade" sin Origen
				if looksVersion(cols[3]) {
					p.Available = cols[3]
				} else {
					p.Source = cols[3]
				}
			}
			if p.ID == "" || !looksID(p.ID) || !looksVersion(p.Version) {
				continue
			}
			res = append(res, p)
		}
		break
	}
	return res
}

var reVer = regexp.MustCompile(`^[<>]?\s*[0-9][0-9A-Za-z.\-+_ ]*$`)

func looksVersion(s string) bool { return s == "Unknown" || s == "Desconocido" || reVer.MatchString(s) }

func looksID(s string) bool {
	if strings.ContainsAny(s, " \t") {
		return false
	}
	return strings.Contains(s, ".") || strings.HasPrefix(s, "MSIX\\") || strings.HasPrefix(s, "ARP\\") || len(s) > 8
}

// splitFallback: Nombre (puede tener espacios) Id Versión [Disponible] [Origen], separados por espacios.
func splitFallback(ln string, ncol int) []string {
	f := strings.Fields(ln)
	if len(f) < ncol {
		return nil
	}
	tail := f[len(f)-(ncol-1):]
	name := strings.Join(f[:len(f)-(ncol-1)], " ")
	return append([]string{name}, tail...)
}

// truncName quita la elipsis que winget pone a los nombres largos.
func truncName(s string) string {
	s = strings.TrimSuffix(s, "…")
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	return strings.TrimSpace(s)
}

// PSList interpreta la salida de ConvertTo-Json: un objeto suelto o una lista.
func PSList[T any](raw string) []T {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	if raw == "" {
		return nil
	}
	var l []T
	if strings.HasPrefix(raw, "[") {
		if json.Unmarshal([]byte(raw), &l) == nil {
			return l
		}
		return nil
	}
	var one T
	if json.Unmarshal([]byte(raw), &one) == nil {
		return []T{one}
	}
	return nil
}

// CompareVersions: -1 si a<b, 0 iguales, 1 si a>b. Compara por números ("1.10" > "1.9").
func CompareVersions(a, b string) int {
	pa, pb := splitVer(a), splitVer(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}

func splitVer(s string) []int {
	var out []int
	n, in := 0, false
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
			in = true
			if n > 1e8 {
				n = 1e8
			}
		} else if in {
			out = append(out, n)
			n, in = 0, false
		}
	}
	if in {
		out = append(out, n)
	}
	return out
}
