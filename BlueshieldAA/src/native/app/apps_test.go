package main

import "testing"

func TestApps(t *testing.T) {
	l := []InstalledApp{
		{Name: "7-Zip 24.08 (x64)", Version: "24.08", Publisher: "Igor Pavlov", Size: 5 << 20},
		{Name: "7-Zip 24.08 (x64)", Version: "24.08"},
		{Name: "Microsoft Visual C++ 2015-2022 Redistributable (x64)", Version: "14.40"},
		{Name: "Google Chrome", Version: "130.0.1"},
		{Name: "  "},
	}
	out := MergeApps(l, map[string]string{"7-zip": "25.01", "google chrome": "130.0.1"})
	if len(out) != 3 {
		t.Fatalf("%d", len(out))
	}
	if out[0].Name != "7-Zip 24.08 (x64)" || out[0].Update != "25.01" || out[0].Size != 5<<20 {
		t.Errorf("%+v", out[0])
	}
	if out[1].Update != "" || out[2].Kind != "Componente" || out[1].Kind != "Programa" {
		t.Errorf("%+v %+v", out[1], out[2])
	}
	if ParseInstallDate("20241105") != "2024-11-05" || ParseInstallDate("5/11/2024") != "" {
		t.Error("fecha")
	}
	if n, v, _ := StoreAppName("SpotifyAB.SpotifyMusic_1.250.0.0_x64__zpdnekdrzrea0"); n != "SpotifyAB.SpotifyMusic" || v != "1.250.0.0" {
		t.Error(n, v)
	}
	if !StoreHidden("Microsoft.VCLibs.140.00_14.0.33519.0_x64__8wekyb3d8bbwe") || StoreHidden("SpotifyAB.SpotifyMusic_1_x64__z") {
		t.Error("ocultas")
	}
}
