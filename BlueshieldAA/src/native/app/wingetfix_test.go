package main

import "testing"

func TestInterpretWinget(t *testing.T) {
	obs := "Encontrado OBS Studio [OBSProject.OBSStudio] Versión 33.0.3\nEl hash del instalador se verificó correctamente\nIniciando instalación de paquete...\nError del instalador con el código de salida: 6\n"
	r := InterpretWinget(obs, int(int32(-1978335226))) // 0x8A150006
	if r.OK || r.InstCode != 6 || !r.InUse {
		t.Errorf("OBS: %+v", r)
	}
	if r := InterpretWinget("El hash del instalador se verificó correctamente\nInstalado correctamente\n", 0); !r.OK {
		t.Errorf("ok: %+v", r)
	}
	if r := InterpretWinget("x", int(int32(-1978334967))); !r.OK || !r.Reboot { // 0x8A150109
		t.Errorf("reinicio: %+v", r)
	}
	if r := InterpretWinget("Error del instalador con el código de salida: 1618", 1); !r.Retry {
		t.Errorf("1618: %+v", r)
	}
}

func TestProcMatch(t *testing.T) {
	k := NameKey("OBS Studio (x64)")
	if k != "obs studio" {
		t.Fatal(k)
	}
	if !ProcMatches(k, "OBS Studio", "OBS Studio", "obs64.exe") {
		t.Error("obs")
	}
	if ProcMatches(k, "Microsoft® Windows® Operating System", "Host Process", "svchost.exe") {
		t.Error("svchost no es obs")
	}
	if NameKey("7-Zip 24.08 (x64)") != "7-zip" {
		t.Error(NameKey("7-Zip 24.08 (x64)"))
	}
}
