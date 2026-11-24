package main

// Interpretación del resultado de winget (portable, con tests).

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var reInstallerCode = regexp.MustCompile(`(?i)(?:código de salida|exit code)\s*:?\s*(-?\d+)`)

type WingetResult struct {
	OK       bool   // instalado
	Reboot   bool   // necesita reiniciar
	Retry    bool   // merece la pena reintentar en un rato (otra instalación en curso)
	InUse    bool   // el programa (o un archivo suyo) está en uso
	Message  string // explicación para el usuario
	Code     int    // código de winget
	InstCode int    // código del instalador (si lo dice)
}

// InterpretWinget decide si winget instaló, y si no, por qué, sin fiarse de palabras sueltas.
func InterpretWinget(out string, code int) WingetResult {
	r := WingetResult{Code: code, InstCode: -1}
	if m := reInstallerCode.FindStringSubmatch(out); m != nil {
		r.InstCode, _ = strconv.Atoi(m[1])
	}
	lo := strings.ToLower(out)
	uc := uint32(code)
	switch {
	case code == 0 && r.InstCode <= 0 && !strings.Contains(lo, "error del instalador") && !strings.Contains(lo, "installer failed"):
		r.OK = true
		return r
	case uc == 0x8A150109 || uc == 0x8A15010A || uc == 0x8A15010B || r.InstCode == 3010 || r.InstCode == 1641:
		r.OK, r.Reboot = true, true
		r.Message = "Instalado; termina de aplicarse al reiniciar el equipo."
		return r
	}
	switch {
	case uc == 0x8A15002B || strings.Contains(lo, "no applicable upgrade") || strings.Contains(lo, "no se encontró ninguna actualización disponible"):
		r.Message = "winget no encuentra una versión nueva aplicable a este equipo (puede que ya esté al día o que el paquete no permita actualizar)."
	case uc == 0x8A150101 || uc == 0x8A150111 || uc == 0x8A150103 || r.InstCode == 1601:
		r.InUse = true
		r.Message = "El programa o alguno de sus archivos está en uso. Ciérralo y vuelve a intentarlo."
	case uc == 0x8A150102 || r.InstCode == 1618:
		r.Retry = true
		r.Message = "Hay otra instalación en marcha en Windows (por ejemplo Windows Update). Se puede volver a intentar en unos minutos."
	case uc == 0x8A150105 || r.InstCode == 112:
		r.Message = "No hay espacio suficiente en el disco."
	case uc == 0x8A150107:
		r.Message = "No hay conexión a Internet para descargar el instalador."
	case uc == 0x8A15010F:
		r.Message = "Una directiva de la empresa bloquea esta instalación."
	case uc == 0x8A15010C || r.InstCode == 1602:
		r.Message = "La instalación se canceló."
	case uc == 0x8A150011 || strings.Contains(lo, "hash"):
		if !strings.Contains(lo, "se verificó correctamente") && !strings.Contains(lo, "successfully verified") {
			r.Message = "El instalador descargado no coincide con la huella publicada y se ha descartado por seguridad. Suele arreglarse solo cuando el fabricante actualiza el paquete."
		}
	case r.InstCode == 1603:
		r.Message = "El instalador falló (error 1603 de Windows Installer). Suele ser un archivo en uso, permisos o una versión anterior dañada."
	case r.InstCode == 1638:
		r.Message = "Ya hay otra versión instalada que impide esta (error 1638). Desinstala la anterior y vuelve a instalar."
	}
	if r.Message == "" {
		if r.InstCode > 0 {
			r.InUse = true // la causa más habitual de que un instalador devuelva un código propio
			r.Message = fmt.Sprintf("El instalador del fabricante terminó con el código %d. Casi siempre significa que el programa (o algo que lo usa) estaba abierto: ciérralo y vuelve a intentarlo.", r.InstCode)
		} else {
			r.Message = fmt.Sprintf("winget terminó con el código 0x%X.", uc)
		}
	}
	return r
}

var reParen = regexp.MustCompile(`\s*\([^)]*\)`)

// NameKeys: nombre "limpio" de un paquete para buscar su proceso ("OBS Studio (x64)" → "obs studio").
func NameKey(name string) string {
	n := strings.ToLower(reParen.ReplaceAllString(name, ""))
	n = strings.TrimSuffix(strings.TrimSpace(n), "…")
	f := strings.Fields(n)
	// fuera versiones sueltas al final ("7-zip 24.08")
	for len(f) > 1 && len(f[len(f)-1]) > 0 && (f[len(f)-1][0] >= '0' && f[len(f)-1][0] <= '9') {
		f = f[:len(f)-1]
	}
	return strings.Join(f, " ")
}

// ProcMatches dice si un proceso (producto/descripción/nombre) pertenece al programa.
func ProcMatches(key, product, desc, exe string) bool {
	if len(key) < 3 {
		return false
	}
	for _, s := range []string{strings.ToLower(product), strings.ToLower(desc)} {
		s = strings.TrimSpace(strings.ReplaceAll(s, "®", ""))
		if s == "" || strings.Contains(s, "windows") && strings.Contains(s, "operating system") {
			continue
		}
		if strings.Contains(s, key) || (len(s) >= 4 && strings.Contains(key, s)) {
			return true
		}
	}
	// nombre del ejecutable: "obs64" ↔ "obs studio"
	e := strings.ToLower(strings.TrimSuffix(exe, ".exe"))
	first := strings.Fields(key)[0]
	return len(first) >= 3 && strings.HasPrefix(e, first)
}
