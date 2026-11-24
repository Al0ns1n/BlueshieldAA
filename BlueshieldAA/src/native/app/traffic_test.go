package main

import "testing"

func TestTrafficCategorias(t *testing.T) {
	if AppCategory("chrome", "") != "Navegador" || AppCategory("svchost", `C:\Windows\System32\svchost.exe`) != "Sistema Windows" ||
		AppCategory("raro", `C:\Windows\System32\raro.exe`) != "Sistema Windows" || AppCategory("x", `D:\SteamLibrary\steamapps\common\x\x.exe`) != "Juegos" || AppCategory("cosa", "") != "Otros programas" {
		t.Error("categorías de programa")
	}
	if SvcCategory(443) != "Web segura" || SvcCategory(53) != "DNS" || SvcCategory(3389) != "Acceso remoto" || SvcCategory(27015) != "Juegos" {
		t.Error("categorías de servicio")
	}
	if q := CymruQuery("8.8.4.1"); q != "1.4.8.8.origin.asn.cymru.com" {
		t.Error(q)
	}
	if q := CymruQuery("2001:db8::1"); q[:4] != "1.0." || q[len(q)-21:] != "origin6.asn.cymru.com" {
		t.Error(q)
	}
	if a, c := ParseCymruOrigin("15169 | 8.8.8.0/24 | US | arin | 1992-12-01"); a != "15169" || c != "US" {
		t.Error(a, c)
	}
	if o := ParseCymruAS("15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"); o != "Google" {
		t.Error(o)
	}
	if o := ParseCymruAS("12345 | ES | ripe | 2001-01-01 | EJEMPLO-AS Ejemplo Telecom SL, ES"); o != "EJEMPLO-AS Ejemplo Telecom SL" {
		t.Error(o)
	}
}
