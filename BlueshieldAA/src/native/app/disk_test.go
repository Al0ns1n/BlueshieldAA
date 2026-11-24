package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClassifyPath(t *testing.T) {
	old := time.Now().AddDate(0, -3, 0)
	cases := []struct {
		p     string
		dir   bool
		level string
		act   string
	}{
		{`C:\Users\usuario\AppData\Local\Temp`, true, LvlBorrar, ""},
		{`C:\$Recycle.Bin`, true, LvlBorrar, ""},
		{`C:\Users\usuario\AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data`, true, LvlBorrar, ""},
		{`C:\Windows\SoftwareDistribution\Download`, true, LvlBorrar, ""},
		{`C:\hiberfil.sys`, false, LvlCuidado, "hiber"},
		{`C:\pagefile.sys`, false, LvlSistema, ""},
		{`C:\Windows\WinSxS`, true, LvlSistema, "dism"},
		{`C:\Windows.old`, true, LvlBorrar, "storage"},
		{`C:\Windows\System32`, true, LvlSistema, ""},
		{`C:\Program Files\OBS`, true, LvlSistema, ""},
		{`C:\Users\usuario\Documents\tesis.docx`, false, LvlPersonal, ""},
		{`C:\Users\usuario\Downloads\setup-viejo.exe`, false, LvlCuidado, ""},
		{`C:\Users\usuario\proyectos\web\node_modules`, true, LvlCuidado, ""},
		{`C:\Users\usuario\AppData\Roaming\discord\Code Cache`, true, LvlBorrar, ""},
		{`C:\Users\usuario\AppData\Roaming\Microsoft`, true, LvlNormal, ""},
		{`D:\Juegos\steamapps\shadercache`, true, LvlBorrar, ""},
	}
	for _, c := range cases {
		got := ClassifyPath(c.p, c.dir, 1<<20, old)
		if got.Level != c.level || got.Action != c.act {
			t.Errorf("%s → %+v (esperaba %s/%s)", c.p, got, c.level, c.act)
		}
	}
	if !ClassifyPath(`C:\Users\a\AppData\Local\Temp`, true, 0, old).Inside || ClassifyPath(`C:\Users\a\AppData\Local\Temp\x.tmp`, false, 0, old).Inside {
		t.Error("Inside")
	}
	if ok, _ := CanDelete(`C:\Windows\System32`, true); ok {
		t.Error("System32 borrable")
	}
	if ok, _ := CanDelete(`C:\Users\usuario\Documents`, true); ok {
		t.Error("Documentos borrable entero")
	}
	if ok, _ := CanDelete(`C:\Users\usuario\Documents\viejo.zip`, false); !ok {
		t.Error("un archivo de Documentos sí se puede")
	}
}

func TestDiskScan(t *testing.T) {
	root := t.TempDir()
	mk := func(p string, n int) {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, make([]byte, n), 0o644)
	}
	mk("a/grande.bin", 300000)
	mk("a/b/x.txt", 1000)
	mk("Temp/basura1.tmp", 5000)
	mk("Temp/sub/basura2.tmp", 7000)
	for i := 0; i < 70; i++ {
		mk("muchos/f"+itoa(i)+".txt", 10+i)
	}
	s := &DiskScan{}
	s.Scan(root)
	p := s.Progress()
	if p.State != "listo" || p.Files != 74 {
		t.Fatalf("progreso %+v", p)
	}
	v, _ := s.View("")
	if v.Entries[0].Name != "a" || v.Self.Size != 300000+1000+12000+int64(70*10+70*69/2) {
		t.Errorf("vista raíz %+v", v.Self)
	}
	m, _ := s.View(filepath.Join(root, "muchos"))
	var last DEntry
	for _, e := range m.Entries {
		if e.Rest {
			last = e
		}
	}
	if !last.Rest || !strings.Contains(last.Name, "10") || last.Size != 145 {
		t.Errorf("otros archivos: %+v", last)
	}
	// borrar el contenido de Temp y comprobar lo liberado
	res := &DeleteResult{}
	deleteInside(filepath.Join(root, "Temp"), res)
	if res.Freed != 12000 || res.Failed != 0 {
		t.Errorf("borrado %+v", res)
	}
	if _, err := os.Stat(filepath.Join(root, "Temp")); err != nil {
		t.Error("la carpeta Temp tiene que quedarse")
	}
	s.Rescan(filepath.Join(root, "Temp"))
	v, _ = s.View("")
	base := 300000 + 1000 + int64(70*10+70*69/2)
	if v.Self.Size != base {
		t.Errorf("tras borrar: %d", v.Self.Size)
	}
	// algo vuelve a escribir en Temp (programa abierto): se ve lo que hay de verdad
	os.WriteFile(filepath.Join(root, "Temp", "nuevo.tmp"), make([]byte, 500), 0o644)
	s.Rescan(filepath.Join(root, "Temp"))
	if v, _ = s.View(""); v.Self.Size != base+500 {
		t.Errorf("tras volver a medir: %d", v.Self.Size)
	}
	// carpeta borrada entera y archivo suelto borrado
	os.RemoveAll(filepath.Join(root, "Temp"))
	s.Rescan(filepath.Join(root, "Temp"))
	if v, _ = s.View(""); v.Self.Size != base {
		t.Errorf("carpeta borrada: %d", v.Self.Size)
	}
	for _, e := range v.Entries {
		if e.Name == "Temp" {
			t.Error("Temp sigue en la vista")
		}
	}
}
