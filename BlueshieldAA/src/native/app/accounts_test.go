package main

import "testing"

func TestAccounts(t *testing.T) {
	var s AccountSet
	for _, c := range ChromiumAccounts([]byte(`{"profile":{"info_cache":{"Default":{"user_name":"Ana.Garcia@gmail.com","gaia_name":"Ana García"},"Profile 1":{"user_name":"","name":"Persona 1"}}}}`)) {
		s.Add(c[0], c[1], "Google Chrome", "google")
	}
	s.Add("ana.garcia@gmail.com", "", "Brave", "google")
	s.Add("ana@empresa.es", "", "Office", "aad")
	s.Add("ana@outlook.es", "", "Windows", "msa")
	s.Add(FirefoxAccount([]byte(`{"version":1,"accountData":{"email":"ana@proton.me"}}`)), "", "Firefox", "")
	for _, m := range ThunderbirdAccounts([]byte(`user_pref("mail.identity.id1.useremail", "info@ejemplo.com");`)) {
		s.Add(m, "", "Thunderbird", "")
	}
	s.Add("no es un correo", "", "x", "")
	l := s.List()
	if len(l) != 5 {
		t.Fatalf("%d %+v", len(l), l)
	}
	if l[0].Email != "ana.garcia@gmail.com" || l[0].Name != "Ana García" || len(l[0].Sources) != 2 || len(l[0].Links) == 0 {
		t.Errorf("%+v", l[0])
	}
	if l[1].Provider != "Microsoft" || l[2].Provider != "Microsoft (trabajo o centro educativo)" || l[4].Provider != "Otro" || len(l[4].Links) != 0 {
		t.Errorf("%+v", l)
	}
}
