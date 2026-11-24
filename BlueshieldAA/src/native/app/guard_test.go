package main

import (
	"archive/zip"
	"bytes"
	"image/jpeg"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDecoysValidos(t *testing.T) {
	for _, n := range decoyNames {
		b := DecoyBytes(n, "PC1")
		switch filepath.Ext(n) {
		case ".docx", ".xlsx":
			if _, err := zip.NewReader(bytes.NewReader(b), int64(len(b))); err != nil {
				t.Errorf("%s no es un zip válido", n)
			}
		case ".jpg":
			if _, err := jpeg.Decode(bytes.NewReader(b)); err != nil {
				t.Errorf("%s no es un JPEG válido", n)
			}
		case ".pdf":
			if !bytes.HasPrefix(b, []byte("%PDF")) || !bytes.Contains(b, []byte("%%EOF")) {
				t.Errorf("pdf")
			}
		}
		// el motor de análisis no debe ver nada raro en un señuelo
		if r := AnalyzeBytes(n, b, int64(len(b))); r.Score > 0 {
			t.Errorf("%s puntúa %d", n, r.Score)
		}
	}
}

func TestCheckDecoys(t *testing.T) {
	d := t.TempDir()
	var list []Decoy
	for _, n := range []string{"!0000_Presupuesto_2026.docx", "zzzz_Claves_banco.txt", "zzzz_Contrato_firmado.pdf"} {
		p := filepath.Join(d, n)
		os.WriteFile(p, DecoyBytes(n, "x"), 0o644)
		fi, _ := os.Stat(p)
		list = append(list, Decoy{p, fi.Size(), fi.ModTime().Unix()})
	}
	if ev := CheckDecoys(list); len(ev) != 0 {
		t.Fatalf("sin cambios: %+v", ev)
	}
	// uno borrado a mano: no es ataque
	os.Remove(list[1].Path)
	ev := CheckDecoys(list)
	if len(ev) != 1 || ev[0].Kind != "borrado" || IsAttack(ev) {
		t.Errorf("borrado suelto: %+v", ev)
	}
	// uno cifrado y renombrado: ataque
	os.WriteFile(list[0].Path+".locked", []byte("cifrado"), 0o644)
	os.Remove(list[0].Path)
	ev = CheckDecoys(list)
	if !IsAttack(ev) || ev[0].Kind != "renombrado" {
		t.Errorf("renombrado: %+v", ev)
	}
	// uno modificado en su sitio
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(list[2].Path, []byte("XXXXXXXX"), 0o644)
	if ev := CheckDecoys(list[2:]); len(ev) != 1 || ev[0].Kind != "modificado" {
		t.Errorf("modificado: %+v", ev)
	}
}

func TestRansomCommandYContencion(t *testing.T) {
	if RansomCommand(`C:\Windows\system32\vssadmin.exe  Delete Shadows /All /Quiet`) == "" {
		t.Error("vssadmin")
	}
	if RansomCommand(`bcdedit /set {default} recoveryenabled No`) == "" {
		t.Error("bcdedit")
	}
	if RansomCommand(`vssadmin list shadows`) != "" {
		t.Error("listar no es ataque")
	}
	cfg := &GuardConfig{InstallDir: `C:\Program Files\BlueShieldAA`}
	cases := []struct {
		n, p, s, c string
		us, want   bool
	}{
		{"explorer.exe", `C:\Windows\explorer.exe`, "Microsoft", "Microsoft Corporation", false, true},
		{"powershell.exe", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "Microsoft", "Microsoft Corporation", false, false},
		{"powershell.exe", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "Microsoft", "Microsoft Corporation", true, true},
		{"chrome.exe", `C:\Program Files\Google\Chrome\Application\chrome.exe`, "Firmado", "Google LLC", false, false},
		{"ekrn.exe", `C:\Program Files\ESET\ESET Security\ekrn.exe`, "Firmado", "ESET, spol. s r.o.", false, true},
		{"BlueShieldAA.exe", `C:\Program Files\BlueShieldAA\BlueShieldAA.exe`, "Sin firmar", "", false, true},
		{"cifrador.exe", `C:\Users\a\AppData\Local\Temp\cifrador.exe`, "Sin firmar", "", false, false},
		{"csrss.exe", "", "", "", false, true},
	}
	for _, c := range cases {
		if got := AllowedInLockdown(c.n, c.p, c.s, c.c, cfg, c.us); got != c.want {
			t.Errorf("%s (%s): %v", c.n, c.p, got)
		}
	}
	if ok, _ := FolderAllowed(`C:\Users\usuario\OneDrive - Personal\Documentos`); ok {
		t.Error("OneDrive")
	}
	if ok, _ := FolderAllowed(`C:\Users\usuario\Documents`); !ok {
		t.Error("Documentos")
	}
	_ = strings.ToLower
}

func TestServiceExeYLiberar(t *testing.T) {
	cases := map[string]string{
		`"C:\Program Files\Foo\foo svc.exe" -k run`:       `C:\Program Files\Foo\foo svc.exe`,
		`%SystemRoot%\system32\svchost.exe -k netsvcs -p`: `C:\Windows\system32\svchost.exe`,
		`\SystemRoot\System32\drivers\x.sys`:              `C:\Windows\System32\drivers\x.sys`,
		`C:\Program Files\Bar\bar.exe /service`:           `C:\Program Files\Bar\bar.exe`,
	}
	for in, want := range cases {
		if got := ServiceExe(in, `C:\Windows`); got != want {
			t.Errorf("%q → %q", in, got)
		}
	}
	if MustStopService("LanmanServer", "Microsoft", "Microsoft Corporation") == "" || MustStopService("WinDefend", "Microsoft", "Microsoft Corporation") != "" {
		t.Error("servicios de Microsoft")
	}
	if MustStopService("ekrn", "Firmado", "ESET, spol. s r.o.") != "" || MustStopService("AnyDesk", "Firmado", "philandro Software GmbH") == "" {
		t.Error("servicios de terceros")
	}
	since := time.Now().Add(-time.Hour)
	c := Containment{Active: true, Since: since, Culprits: []Culprit{{Name: "x.exe", Quarantined: true}}}
	scan := ScanState{End: time.Now(), OK: true}
	if !CanRelease(ReleaseChecks(c, scan, nil, nil, 0, false, false)) {
		t.Error("todo bien debería poder liberarse")
	}
	if CanRelease(ReleaseChecks(c, ScanState{End: since.Add(-time.Minute), OK: true}, nil, nil, 0, false, false)) {
		t.Error("análisis anterior al ataque no vale")
	}
	if CanRelease(ReleaseChecks(c, scan, nil, []string{"HKLM Run: x"}, 0, false, false)) || !CanRelease(ReleaseChecks(c, scan, nil, []string{"x"}, 0, true, false)) {
		t.Error("inicio automático")
	}
	if CanRelease(ReleaseChecks(c, scan, []string{"x.exe"}, nil, 0, false, false)) || CanRelease(ReleaseChecks(c, scan, nil, nil, 1, false, false)) {
		t.Error("culpable o señuelos")
	}
}
