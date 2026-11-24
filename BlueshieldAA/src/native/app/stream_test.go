package main

import "testing"

func TestStreamAndProgress(t *testing.T) {
	var lines []string
	var crs []bool
	ls := &LineSplitter{Emit: func(l string, cr bool) { lines = append(lines, l); crs = append(crs, cr) }}
	ls.Write([]byte("Encontrado Bitwarden [Bitwarden.Bitwarden] Versión 2026.11.0\r\n-\r\\\r  ██████▒▒▒▒  40.0 MB / 98.5 MB\r  ██████████  98.5 MB / 98.5 MB\r\nInstalado correctamente\r\n"))
	ls.Close()
	if lines[0] != "Encontrado Bitwarden [Bitwarden.Bitwarden] Versión 2026.11.0" {
		t.Errorf("%q", lines[0])
	}
	p, txt, ok := ParseProgress("  ██████▒▒▒▒  40.0 MB / 98.5 MB")
	if !ok || p != 40 || txt != "Descargando 40.0 MB de 98.5 MB" {
		t.Errorf("progreso %d %q %v", p, txt, ok)
	}
	if p, _, ok := ParseProgress("  ███████████▒▒▒▒▒▒▒▒▒  55%"); !ok || p != 55 {
		t.Errorf("pct %d", p)
	}
	if _, _, ok := ParseProgress("Instalado correctamente"); ok {
		t.Error("texto no es progreso")
	}
	if !IsNoise("  \\ ") || IsNoise("Hola") {
		t.Error("ruido")
	}
	if decodeConsole([]byte{'V', 'e', 'r', 's', 0xa2, 'n'}) != "Versón" && decodeConsole([]byte{0x82}) != "é" {
		t.Error("cp850")
	}
	if wingetStage("Iniciando instalación del paquete...") != "Instalando" {
		t.Error("etapa")
	}
}
