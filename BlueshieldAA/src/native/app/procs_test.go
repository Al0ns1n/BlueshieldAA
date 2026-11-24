package main

import "testing"

func TestProcs(t *testing.T) {
	p := ProcRow{Name: "svchost.exe", Path: `C:\Users\ana\AppData\Roaming\svchost.exe`}
	ClassifyProc(&p)
	if p.Flag != "Alerta" {
		t.Error("svchost falso")
	}
	p = ProcRow{Name: "chrome.exe", Path: `C:\Program Files\Google\Chrome\Application\chrome.exe`, Signed: "Firmado", Conns: 20}
	ClassifyProc(&p)
	if p.Flag != "" {
		t.Error("chrome normal")
	}
	p = ProcRow{Name: "setup.exe", Path: `C:\Users\ana\Downloads\setup.exe`, Signed: "Sin firmar"}
	ClassifyProc(&p)
	if p.Flag != "Alerta" {
		t.Error("descargas sin firmar")
	}
	tr := ProcTree([]ProcRow{{PID: 1, Name: "b"}, {PID: 2, PPID: 1, Name: "hijo"}, {PID: 3, Name: "a"}})
	if tr[0].Name != "a" || tr[2].Name != "hijo" || tr[2].Depth != 1 {
		t.Errorf("%+v", tr)
	}
}
