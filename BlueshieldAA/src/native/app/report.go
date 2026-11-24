package main

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"
)

// Relación orientativa entre apartados y medidas del ENS (RD 311/2022) y el art. 21 de NIS2.
var complianceMap = []struct {
	Cats []string
	ENS  string
	NIS2 string
	Name string
}{
	{[]string{"Programas", "Windows", "Vulnerabilidades"}, "op.exp.4 Mantenimiento y actualizaciones", "21.2.e Gestión de vulnerabilidades", "Actualizaciones y parches"},
	{[]string{"Seguridad"}, "op.exp.6 Protección frente a código dañino · mp.eq.1-3", "21.2.e / 21.2.g Ciberhigiene", "Antivirus, firewall, cifrado y UAC"},
	{[]string{"Endurecimiento"}, "op.exp.2 Configuración de seguridad · op.acc.6", "21.2.i Control de acceso", "Bastionado y credenciales"},
	{[]string{"Red", "Intrusiones"}, "mp.com.1 Perímetro seguro · op.mon.1 Detección de intrusión", "21.2.b Gestión de incidentes", "Exposición de red e intentos de acceso"},
	{[]string{"Cambios", "Eventos"}, "op.exp.8 Registro de actividad · op.exp.9", "21.2.b / 21.2.f", "Registro y cambios en el equipo"},
	{[]string{"Hardware", "Limpieza"}, "mp.eq.2 · op.cont", "21.2.c Continuidad", "Salud del equipo y espacio"},
}

func BuildReportHTML(items []*Item, computer string, compliance bool) string {
	esc := html.EscapeString
	var sb strings.Builder
	title := ternary(compliance, "Informe de cumplimiento (orientativo ENS / NIS2)", "Informe de seguridad del equipo")
	sb.WriteString(`<!doctype html><html lang="es"><head><meta charset="utf-8"><title>` + esc(title) + `</title><style>
body{font-family:Segoe UI,Arial,sans-serif;margin:40px;color:#1f2328;max-width:1100px}h1{margin:0}p.s{color:#57606a;margin:4px 0 24px}
.kpi{display:flex;gap:14px;margin:18px 0}.kpi div{border:1px solid #d0d7de;border-radius:10px;padding:12px 16px;min-width:130px}.kpi b{display:block;font-size:26px}
table{border-collapse:collapse;width:100%;margin:10px 0 26px;font-size:13px}th,td{border-bottom:1px solid #e5e7eb;padding:7px 8px;text-align:left;vertical-align:top}th{background:#f6f8fa}
.st{font-weight:600;border-radius:6px;padding:2px 8px;font-size:12px;white-space:nowrap}.bad{background:#ffebe9;color:#b42318}.warn{background:#fff4d6;color:#8a5a00}.ok{background:#e7f7ee;color:#0b7a52}.info{background:#eef2ff;color:#3538cd}
h2{margin-top:30px;border-bottom:2px solid #0f6cbd;padding-bottom:4px}.note{color:#57606a;font-size:12px}
@media print{body{margin:10mm}}</style></head><body>`)
	sb.WriteString("<h1>" + esc(title) + "</h1>")
	sb.WriteString(fmt.Sprintf(`<p class="s">Equipo <b>%s</b> · %s · BlueShieldAA %s</p>`, esc(computer), time.Now().Format("02/01/2006 15:04"), AppVersion))
	bad, warn := 0, 0
	for _, i := range items {
		if i.Status == "Vulnerable" || i.Status == "Falló" {
			bad++
		} else if pendingStatus[i.Status] {
			warn++
		}
	}
	sb.WriteString(fmt.Sprintf(`<div class="kpi"><div>Puntuación<b>%d / 100</b></div><div>Graves<b style="color:#b42318">%d</b></div><div>Avisos<b style="color:#8a5a00">%d</b></div><div>Elementos revisados<b>%d</b></div></div>`, Score(items), bad, warn, len(items)))
	cls := func(s string) string {
		switch s {
		case "Vulnerable", "Falló", "Error":
			return "bad"
		case "Actualizar", "Revisar", "Abierto", "Pendiente":
			return "warn"
		case "Al día", "Actualizado", "Limpio":
			return "ok"
		}
		return "info"
	}
	row := func(it *Item) string {
		v := ""
		if it.Current != "-" {
			v = it.Current
			if it.Available != "-" && it.Available != "" {
				v += " → " + it.Available
			}
		}
		return fmt.Sprintf(`<tr><td><span class="st %s">%s</span></td><td><b>%s</b><div class="note">%s</div></td><td>%s</td></tr>`, cls(it.Status), esc(ternary(it.Status == "Al día" && (it.Category == "Endurecimiento"), "Corregida", it.Status)), esc(it.Name), esc(firstSentence(it.Detail)), esc(v))
	}
	if compliance {
		sb.WriteString(`<p class="note">Relación orientativa entre lo que comprueba BlueShieldAA en este equipo y medidas del Esquema Nacional de Seguridad (RD 311/2022) y del art. 21 de la Directiva NIS2. No sustituye a una auditoría: cubre solo el puesto de trabajo, no la organización.</p>`)
		sb.WriteString(`<table><tr><th>Área</th><th>ENS</th><th>NIS2</th><th>Estado</th></tr>`)
		for _, m := range complianceMap {
			n, p := 0, 0
			for _, it := range items {
				for _, c := range m.Cats {
					if it.Category == c {
						n++
						if pendingStatus[it.Status] {
							p++
						}
					}
				}
			}
			st := `<span class="st ok">Cumple</span>`
			if n == 0 {
				st = `<span class="st info">Sin datos</span>`
			} else if p > 0 {
				st = fmt.Sprintf(`<span class="st warn">%d pendiente(s)</span>`, p)
			}
			sb.WriteString(fmt.Sprintf("<tr><td><b>%s</b></td><td>%s</td><td>%s</td><td>%s</td></tr>", esc(m.Name), esc(m.ENS), esc(m.NIS2), st))
		}
		sb.WriteString("</table>")
	}
	cats := map[string][]*Item{}
	var order []string
	for _, it := range items {
		if it.Status == "Oculto" {
			continue
		}
		if _, ok := cats[it.Category]; !ok {
			order = append(order, it.Category)
		}
		cats[it.Category] = append(cats[it.Category], it)
	}
	sort.Strings(order)
	for _, c := range order {
		sb.WriteString("<h2>" + esc(c) + "</h2><table><tr><th style=\"width:110px\">Estado</th><th>Elemento</th><th style=\"width:200px\">Valor</th></tr>")
		for _, it := range cats[c] {
			sb.WriteString(row(it))
		}
		sb.WriteString("</table>")
	}
	sb.WriteString(`<p class="note">Generado por BlueShieldAA. Para guardarlo en PDF: Ctrl+P → Guardar como PDF.</p></body></html>`)
	return sb.String()
}

func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ". "); i > 0 && i < 220 {
		return s[:i+1]
	}
	if len([]rune(s)) > 220 {
		return string([]rune(s)[:220]) + "…"
	}
	return s
}
