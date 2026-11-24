package main

// Mis cuentas: las cuentas de correo y de servicios que hay en este equipo (Windows, Office,
// navegadores, correo) y los enlaces oficiales para ver su actividad, dispositivos y ubicación.
// No se inicia sesión en nada ni se usan claves: Google y Microsoft no dejan leer el historial de
// inicios de sesión de una cuenta personal sin registrar una aplicación con claves.

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

type AcctLink struct {
	T   string `json:"t"`
	URL string `json:"url"`
	D   string `json:"d"`
}

type Account struct {
	Email    string     `json:"email"`
	Name     string     `json:"name,omitempty"`
	Provider string     `json:"provider"` // Google, Microsoft, Microsoft (trabajo o centro educativo), Apple, Yahoo, Otro
	Sources  []string   `json:"sources"`
	Links    []AcctLink `json:"links"`
}

var reEmail = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$`)

// ProviderOf deduce el proveedor por el dominio o por dónde se encontró.
func ProviderOf(email, hint string) string {
	d := strings.ToLower(email[strings.LastIndex(email, "@")+1:])
	switch {
	case d == "gmail.com" || d == "googlemail.com" || hint == "google":
		return "Google"
	case hasAny(d, "outlook.", "hotmail.", "live.", "msn.com") || hint == "msa":
		return "Microsoft"
	case hint == "aad":
		return "Microsoft (trabajo o centro educativo)"
	case d == "icloud.com" || d == "me.com" || d == "mac.com":
		return "Apple"
	case strings.HasPrefix(d, "yahoo.") || d == "ymail.com":
		return "Yahoo"
	case d == "proton.me" || d == "protonmail.com":
		return "Proton"
	}
	return "Otro"
}

// AccountLinks: páginas oficiales donde ver dónde y desde qué dispositivos se ha entrado.
func AccountLinks(provider string) []AcctLink {
	switch provider {
	case "Google":
		return []AcctLink{{"Dispositivos con la sesión iniciada", "https://myaccount.google.com/device-activity", "Ordenadores y móviles con la cuenta abierta, con ciudad y última actividad. Desde ahí puedes cerrar la sesión de cualquiera."},
			{"Actividad de seguridad reciente", "https://myaccount.google.com/notifications", "Inicios de sesión nuevos, cambios de contraseña y avisos de Google."},
			{"Revisión de seguridad", "https://myaccount.google.com/security-checkup", "Lo que Google recomienda revisar en tu cuenta."}}
	case "Microsoft":
		return []AcctLink{{"Actividad reciente (inicios de sesión)", "https://account.live.com/Activity", "Cada inicio de sesión con fecha, país, IP, navegador y si fue correcto."},
			{"Dispositivos", "https://account.microsoft.com/devices", "Equipos y móviles asociados a la cuenta."},
			{"Seguridad de la cuenta", "https://account.microsoft.com/security", "Contraseña, verificación en dos pasos y métodos de recuperación."}}
	case "Microsoft (trabajo o centro educativo)":
		return []AcctLink{{"Mis inicios de sesión", "https://mysignins.microsoft.com/", "Inicios de sesión con ubicación, aplicación y si fueron correctos (si tu organización lo permite)."},
			{"Mis dispositivos", "https://myaccount.microsoft.com/device-list", "Dispositivos registrados con tu cuenta de trabajo."}}
	case "Apple":
		return []AcctLink{{"Cuenta de Apple: dispositivos", "https://account.apple.com/account/manage/section/devices", "iPhone, iPad y Mac con tu cuenta."}}
	case "Yahoo":
		return []AcctLink{{"Actividad reciente", "https://login.yahoo.com/account/activity", "Inicios de sesión y aplicaciones conectadas."}}
	case "Proton":
		return []AcctLink{{"Sesiones activas", "https://account.proton.me/u/0/mail/account-password", "Sesiones abiertas de tu cuenta Proton."}}
	}
	return nil
}

// AccountSet junta las cuentas encontradas en distintos sitios.
type AccountSet struct{ m map[string]*Account }

func (s *AccountSet) Add(email, name, source, hint string) {
	email = strings.TrimSpace(strings.ToLower(email))
	if !reEmail.MatchString(email) {
		return
	}
	if s.m == nil {
		s.m = map[string]*Account{}
	}
	a, ok := s.m[email]
	if !ok {
		a = &Account{Email: email, Provider: ProviderOf(email, hint), Sources: []string{}}
		s.m[email] = a
	} else if hint == "aad" && a.Provider == "Otro" {
		a.Provider = ProviderOf(email, hint)
	} else if hint == "google" && a.Provider == "Otro" {
		a.Provider = "Google"
	}
	if a.Name == "" && name != "" {
		a.Name = name
	}
	for _, x := range a.Sources {
		if x == source {
			return
		}
	}
	a.Sources = append(a.Sources, source)
}

func (s *AccountSet) List() []Account {
	out := []Account{}
	for _, a := range s.m {
		a.Links = AccountLinks(a.Provider)
		if a.Links == nil {
			a.Links = []AcctLink{}
		}
		out = append(out, *a)
	}
	rank := map[string]int{"Google": 0, "Microsoft": 1, "Microsoft (trabajo o centro educativo)": 2, "Apple": 3}
	sort.Slice(out, func(i, j int) bool {
		ri, ok1 := rank[out[i].Provider]
		rj, ok2 := rank[out[j].Provider]
		if !ok1 {
			ri = 9
		}
		if !ok2 {
			rj = 9
		}
		if ri != rj {
			return ri < rj
		}
		return out[i].Email < out[j].Email
	})
	return out
}

// ChromiumAccounts lee «Local State» de Chrome/Edge/Brave: perfiles con sesión iniciada.
func ChromiumAccounts(localState []byte) [][2]string {
	var v struct {
		Profile struct {
			InfoCache map[string]struct {
				UserName string `json:"user_name"`
				GaiaName string `json:"gaia_name"`
				Name     string `json:"name"`
			} `json:"info_cache"`
		} `json:"profile"`
	}
	if json.Unmarshal(localState, &v) != nil {
		return nil
	}
	var out [][2]string
	for _, p := range v.Profile.InfoCache {
		if p.UserName != "" {
			out = append(out, [2]string{p.UserName, ternary(p.GaiaName != "", p.GaiaName, p.Name)})
		}
	}
	return out
}

// FirefoxAccount lee signedInUser.json de un perfil de Firefox.
func FirefoxAccount(b []byte) string {
	var v struct {
		AccountData struct {
			Email string `json:"email"`
		} `json:"accountData"`
	}
	if json.Unmarshal(b, &v) != nil {
		return ""
	}
	return v.AccountData.Email
}

var reTbMail = regexp.MustCompile(`user_pref\("mail\.identity\.[^"]+\.useremail",\s*"([^"]+)"\)`)

// ThunderbirdAccounts lee prefs.js de Thunderbird.
func ThunderbirdAccounts(prefs []byte) []string {
	var out []string
	for _, m := range reTbMail.FindAllSubmatch(prefs, -1) {
		out = append(out, string(m[1]))
	}
	return out
}
