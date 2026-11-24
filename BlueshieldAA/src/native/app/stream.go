package main

// Lectura en directo de lo que escriben winget, MpCmdRun o PowerShell, para enseñarlo en la
// consola de la ventana de progreso y sacar el porcentaje real de las descargas.

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// LineSplitter corta la salida en líneas. Las barras de progreso se reescriben con \r, así
// que \r también termina una línea (pero se marca como "parcial").
type LineSplitter struct {
	buf  []byte
	Emit func(line string, cr bool)
}

func (ls *LineSplitter) Write(p []byte) (int, error) {
	for _, c := range p {
		switch c {
		case '\n':
			ls.flush(false)
		case '\r':
			ls.flush(true)
		default:
			ls.buf = append(ls.buf, c)
			if len(ls.buf) > 4096 {
				ls.flush(false)
			}
		}
	}
	return len(p), nil
}

func (ls *LineSplitter) Close() { ls.flush(false) }

func (ls *LineSplitter) flush(cr bool) {
	if len(ls.buf) == 0 {
		return
	}
	s := decodeConsole(ls.buf)
	ls.buf = ls.buf[:0]
	if ls.Emit != nil {
		ls.Emit(s, cr)
	}
}

// decodeConsole: winget escribe en UTF-8; otras herramientas en la página de códigos de la
// consola (850 en Windows en español). Si no es UTF-8 válido se traduce desde CP850.
func decodeConsole(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for _, c := range b {
		if c < 0x80 {
			sb.WriteByte(c)
			continue
		}
		sb.WriteRune(cp850[c-0x80])
	}
	return sb.String()
}

var cp850 = []rune("ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜø£Ø×ƒáíóúñÑªº¿®¬½¼¡«»░▒▓│┤ÁÂÀ©╣║╗╝¢¥┐└┴┬├─┼ãÃ╚╔╩╦╠═╬¤ðÐÊËÈıÍÎÏ┘┌█▄¦Ì▀ÓßÔÒõÕµþÞÚÛÙýÝ¯´­±‗¾¶§÷¸°¨·¹³²■ ")

var (
	reSizeProg = regexp.MustCompile(`([\d.,]+)\s*(B|KB|MB|GB)\s*/\s*([\d.,]+)\s*(B|KB|MB|GB)`)
	rePctProg  = regexp.MustCompile(`(\d{1,3})\s*%`)
)

// ParseProgress reconoce las barras de winget ("█████▒▒▒  12.0 MB / 98.5 MB" o "███▒▒ 45%").
func ParseProgress(line string) (pct int, text string, ok bool) {
	t := strings.TrimSpace(line)
	if t == "" {
		return 0, "", false
	}
	bar := strings.ContainsAny(t, "█▒▓░")
	if m := reSizeProg.FindStringSubmatch(t); m != nil {
		a := toBytes(m[1], m[2])
		b := toBytes(m[3], m[4])
		if b > 0 {
			p := int(a * 100 / b)
			return clampInt(p, 0, 100), "Descargando " + m[1] + " " + m[2] + " de " + m[3] + " " + m[4], true
		}
	}
	if bar {
		if m := rePctProg.FindStringSubmatch(t); m != nil {
			p, _ := strconv.Atoi(m[1])
			return clampInt(p, 0, 100), "", true
		}
		// barra sin números: se calcula por los bloques llenos
		full := strings.Count(t, "█")
		total := full + strings.Count(t, "▒") + strings.Count(t, "░")
		if total > 0 {
			return full * 100 / total, "", true
		}
	}
	return 0, "", false
}

func toBytes(n, unit string) float64 {
	n = strings.ReplaceAll(n, ",", ".")
	f, _ := strconv.ParseFloat(n, 64)
	switch unit {
	case "KB":
		f *= 1 << 10
	case "MB":
		f *= 1 << 20
	case "GB":
		f *= 1 << 30
	}
	return f
}

func clampInt(v, a, b int) int {
	if v < a {
		return a
	}
	if v > b {
		return b
	}
	return v
}

// IsNoise: líneas que no aportan nada en la consola (spinner, vacías).
func IsNoise(line string) bool {
	t := strings.TrimSpace(line)
	return t == "" || t == "-" || t == "\\" || t == "|" || t == "/"
}

// wingetStage traduce las líneas de winget a una subtarea corta para la ventana.
func wingetStage(line string) string {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "descargando") || strings.Contains(l, "downloading"):
		return "Descargando el instalador"
	case strings.Contains(l, "hash") && (strings.Contains(l, "verific") || strings.Contains(l, "verified")):
		return "Huella del instalador verificada"
	case strings.Contains(l, "iniciando") || strings.Contains(l, "starting package install"):
		return "Instalando"
	case strings.Contains(l, "correctamente") || strings.Contains(l, "successfully"):
		return "Terminado"
	case strings.Contains(l, "encontrado") || strings.Contains(l, "found "):
		return "Paquete encontrado"
	}
	return ""
}
