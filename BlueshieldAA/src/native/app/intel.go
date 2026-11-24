package main

// Consultas a servicios públicos SIN clave: reputación de huellas, filtraciones y CISA KEV.
// Nunca se envía el archivo: solo su huella. Las contraseñas usan k-anonimato (5 caracteres del SHA-1).

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var httpc = &http.Client{Timeout: 15 * time.Second}

func httpGet(u string, hdr map[string]string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", AppName+"/"+AppVersion)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return b, resp.StatusCode, err
}

// ---------- reputación de archivos ----------

// Reputation consulta varias bases públicas y rellena r.Intel, r.KnownBad, r.KnownGood y r.Reputation.
func Reputation(r *FAResult) {
	type res struct {
		src  string
		bad  string
		good string
		ok   bool
	}
	ch := make(chan res, 3)
	go func() { // Team Cymru Malware Hash Registry (DNS, resume más de 30 antivirus)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		txt, err := net.DefaultResolver.LookupTXT(ctx, r.SHA256+".hash.cymru.com")
		if err != nil {
			txt, err = net.DefaultResolver.LookupTXT(ctx, r.MD5+".hash.cymru.com")
		}
		if err != nil {
			// NXDOMAIN = no conocido como malware
			if de, ok := err.(*net.DNSError); ok && de.IsNotFound {
				ch <- res{src: "Team Cymru", ok: true}
				return
			}
			ch <- res{src: "Team Cymru"}
			return
		}
		for _, t := range txt {
			f := strings.Fields(t)
			if len(f) == 2 {
				if pct, _ := strconv.Atoi(f[1]); pct > 0 {
					ch <- res{src: "Team Cymru", ok: true, bad: fmt.Sprintf("Team Cymru: lo detecta el %d %% de los antivirus", pct)}
					return
				}
			}
		}
		ch <- res{src: "Team Cymru", ok: true}
	}()
	go func() { // AlienVault OTX (sin clave)
		b, code, err := httpGet("https://otx.alienvault.com/api/v1/indicators/file/"+r.SHA256+"/general", nil)
		if err != nil || code >= 500 {
			ch <- res{src: "AlienVault OTX"}
			return
		}
		var v struct {
			PulseInfo struct {
				Count int `json:"count"`
			} `json:"pulse_info"`
		}
		_ = json.Unmarshal(b, &v)
		if v.PulseInfo.Count > 0 {
			ch <- res{src: "AlienVault OTX", ok: true, bad: fmt.Sprintf("AlienVault OTX: aparece en %d informe(s) de amenazas", v.PulseInfo.Count)}
			return
		}
		ch <- res{src: "AlienVault OTX", ok: code == 200 || code == 404}
	}()
	go func() { // CIRCL hashlookup: archivos legítimos publicados (NSRL y otros)
		b, code, err := httpGet("https://hashlookup.circl.lu/lookup/sha256/"+r.SHA256, map[string]string{"accept": "application/json"})
		if err != nil {
			ch <- res{src: "CIRCL hashlookup"}
			return
		}
		if code == 200 {
			var v map[string]any
			_ = json.Unmarshal(b, &v)
			name := ""
			if s, ok := v["FileName"].(string); ok {
				name = s
			}
			if t, ok := v["hashlookup:trust"].(float64); ok && t < 50 {
				ch <- res{src: "CIRCL hashlookup", ok: true}
				return
			}
			ch <- res{src: "CIRCL hashlookup", ok: true, good: strings.TrimSpace("Archivo legítimo publicado " + ternary(name != "", "("+name+")", ""))}
			return
		}
		ch <- res{src: "CIRCL hashlookup", ok: code == 404}
	}()
	var bads, goods []string
	for i := 0; i < 3; i++ {
		x := <-ch
		if x.ok {
			r.Intel = append(r.Intel, x.src)
		} else {
			r.Intel = append(r.Intel, x.src+" (sin respuesta)")
		}
		if x.bad != "" {
			bads = append(bads, x.bad)
		}
		if x.good != "" {
			goods = append(goods, x.good)
		}
	}
	switch {
	case len(bads) > 0:
		r.KnownBad = true
		r.Reputation = strings.Join(bads, " · ")
		r.add("danger", 60, "Malware conocido", r.Reputation)
	case len(goods) > 0:
		r.KnownGood = true
		r.Reputation = goods[0]
	default:
		r.Reputation = "No aparece en las bases de malware consultadas"
	}
}

// ---------- contraseñas ----------

type PwStrength struct {
	Score  int      `json:"score"` // 0..4
	Label  string   `json:"label"`
	Length int      `json:"length"`
	Crack  string   `json:"crack"`
	Tips   []string `json:"tips"`
}

var commonPw = []string{"123456", "password", "contraseña", "qwerty", "111111", "abc123", "iloveyou", "admin", "welcome", "letmein", "monkey", "dragon", "football", "barcelona", "realmadrid", "123456789", "12345678", "000000", "654321", "superman", "passw0rd", "verano", "invierno", "madrid", "españa"}

// PasswordStrength estima la fuerza sin enviar nada (entropía con penalizaciones).
func PasswordStrength(pw string) PwStrength {
	r := []rune(pw)
	n := len(r)
	var low, up, dig, sym bool
	for _, c := range r {
		switch {
		case c >= 'a' && c <= 'z' || c == 'ñ':
			low = true
		case c >= 'A' && c <= 'Z' || c == 'Ñ':
			up = true
		case c >= '0' && c <= '9':
			dig = true
		default:
			sym = true
		}
	}
	pool := 0
	if low {
		pool += 26
	}
	if up {
		pool += 26
	}
	if dig {
		pool += 10
	}
	if sym {
		pool += 33
	}
	bits := 0.0
	if pool > 0 {
		bits = float64(n) * log2f(float64(pool))
	}
	lp := strings.ToLower(pw)
	tips := []string{}
	for _, c := range commonPw {
		if strings.Contains(lp, c) {
			bits = minf(bits, 18+float64(n-len([]rune(c)))*3)
			tips = append(tips, "Contiene una palabra o secuencia muy usada («"+c+"»).")
			break
		}
	}
	// repeticiones y secuencias
	rep := 0
	for i := 1; i < n; i++ {
		if r[i] == r[i-1] || r[i] == r[i-1]+1 {
			rep++
		}
	}
	if n > 0 && rep*2 >= n {
		bits *= 0.6
		tips = append(tips, "Tiene caracteres repetidos o seguidos (aaa, 1234, abcd).")
	}
	// año al final
	if n >= 4 {
		if y, err := strconv.Atoi(string(r[n-4:])); err == nil && y >= 1950 && y <= 2035 {
			bits -= 8
			tips = append(tips, "Termina en un año: es lo primero que prueban los atacantes.")
		}
	}
	if n < 12 {
		tips = append(tips, "Usa al menos 12 caracteres; mejor una frase de 4 o 5 palabras.")
	}
	if !(low && up && dig && sym) && n < 16 {
		tips = append(tips, "Mezcla mayúsculas, minúsculas, números y símbolos, o alárgala.")
	}
	if bits < 0 {
		bits = 0
	}
	score := 0
	switch {
	case bits >= 80:
		score = 4
	case bits >= 60:
		score = 3
	case bits >= 40:
		score = 2
	case bits >= 28:
		score = 1
	}
	labels := []string{"Muy débil", "Débil", "Aceptable", "Fuerte", "Muy fuerte"}
	return PwStrength{Score: score, Label: labels[score], Length: n, Crack: crackTime(bits), Tips: tips}
}

func crackTime(bits float64) string {
	// 10.000 millones de intentos por segundo (hash rápido robado, una GPU potente)
	secs := pow2(bits) / 2 / 1e10
	switch {
	case secs < 1:
		return "menos de un segundo"
	case secs < 60:
		return fmt.Sprintf("%.0f segundos", secs)
	case secs < 3600:
		return fmt.Sprintf("%.0f minutos", secs/60)
	case secs < 86400:
		return fmt.Sprintf("%.0f horas", secs/3600)
	case secs < 86400*365:
		return fmt.Sprintf("%.0f días", secs/86400)
	case secs < 86400*365*1000:
		return fmt.Sprintf("%.0f años", secs/86400/365)
	default:
		return "más de mil años"
	}
}

type PwnedOut struct {
	Count    int         `json:"count"`
	Err      string      `json:"err,omitempty"`
	Strength *PwStrength `json:"strength,omitempty"`
}

// PwnedPassword usa Have I Been Pwned con k-anonimato: solo salen 5 caracteres del SHA-1.
func PwnedPassword(pw string) PwnedOut {
	st := PasswordStrength(pw)
	h := sha1.Sum([]byte(pw))
	hx := strings.ToUpper(hex.EncodeToString(h[:]))
	b, code, err := httpGet("https://api.pwnedpasswords.com/range/"+hx[:5], map[string]string{"Add-Padding": "true"})
	if err != nil || code != 200 {
		return PwnedOut{Err: "No hay conexión con Have I Been Pwned. Inténtalo más tarde.", Strength: &st}
	}
	return PwnedOut{Count: pwnedCount(string(b), hx[5:]), Strength: &st}
}

func pwnedCount(body, suffix string) int {
	for _, ln := range strings.Split(body, "\n") {
		ln = strings.TrimSpace(ln)
		if i := strings.IndexByte(ln, ':'); i > 0 && strings.EqualFold(ln[:i], suffix) {
			n, _ := strconv.Atoi(ln[i+1:])
			return n
		}
	}
	return 0
}

type Breach struct {
	Name     string   `json:"name"`
	Domain   string   `json:"domain"`
	Year     string   `json:"year"`
	Records  int64    `json:"records"`
	Industry string   `json:"industry"`
	Verified bool     `json:"verified"`
	Password bool     `json:"password"`
	PwRisk   string   `json:"pwRisk"`
	Data     []string `json:"data"`
}

type BreachOut struct {
	Breaches []Breach `json:"breaches"`
	Basic    bool     `json:"basic"`
	Err      string   `json:"err,omitempty"`
}

var dataES = map[string]string{"Email addresses": "Correos", "Passwords": "Contraseñas", "Usernames": "Usuarios", "Names": "Nombres", "Phone numbers": "Teléfonos", "IP addresses": "Direcciones IP", "Dates of birth": "Fechas de nacimiento", "Physical addresses": "Direcciones postales", "Genders": "Sexo", "Credit cards": "Tarjetas de crédito", "Bank account numbers": "Cuentas bancarias", "Government issued IDs": "Documentos de identidad", "Security questions and answers": "Preguntas de seguridad", "Geographic locations": "Ubicaciones", "Job titles": "Puestos de trabajo", "Employers": "Empresas", "Social media profiles": "Redes sociales", "Password hints": "Pistas de contraseña", "Partial credit card data": "Datos de tarjeta"}

// BreachedEmail consulta XposedOrNot (gratis y sin clave).
func BreachedEmail(mail string) BreachOut {
	mail = strings.TrimSpace(strings.ToLower(mail))
	if !strings.Contains(mail, "@") || strings.ContainsAny(mail, " /?#") {
		return BreachOut{Err: "Escribe un correo válido."}
	}
	b, code, err := httpGet("https://api.xposedornot.com/v1/breach-analytics?email="+url.QueryEscape(mail), nil)
	if err != nil {
		return BreachOut{Err: "No hay conexión con XposedOrNot. Inténtalo más tarde."}
	}
	if code == 404 {
		return BreachOut{Breaches: []Breach{}}
	}
	if code == 429 {
		return BreachOut{Err: "XposedOrNot ha recibido demasiadas consultas. Espera un minuto."}
	}
	out := parseXON(b)
	if out.Err == "" && len(out.Breaches) == 0 && code != 200 {
		out.Err = fmt.Sprintf("XposedOrNot respondió con un error (%d).", code)
	}
	return out
}

func parseXON(b []byte) BreachOut {
	var v struct {
		ExposedBreaches struct {
			BreachesDetails []struct {
				Breach     string `json:"breach"`
				Domain     string `json:"domain"`
				Industry   string `json:"industry"`
				PasswordRk string `json:"password_risk"`
				XposedData string `json:"xposed_data"`
				XposedDate string `json:"xposed_date"`
				Records    int64  `json:"xposed_records"`
				Verified   string `json:"verified"`
			} `json:"breaches_details"`
		} `json:"ExposedBreaches"`
		Error string `json:"Error"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return BreachOut{Err: "Respuesta no válida de XposedOrNot."}
	}
	if v.Error != "" && strings.Contains(strings.ToLower(v.Error), "not found") {
		return BreachOut{Breaches: []Breach{}}
	}
	out := BreachOut{Breaches: []Breach{}}
	for _, d := range v.ExposedBreaches.BreachesDetails {
		br := Breach{Name: d.Breach, Domain: d.Domain, Year: d.XposedDate, Records: d.Records, Industry: d.Industry, Verified: strings.EqualFold(d.Verified, "yes")}
		for _, x := range strings.Split(d.XposedData, ";") {
			x = strings.TrimSpace(x)
			if x == "" {
				continue
			}
			if es, ok := dataES[x]; ok {
				x = es
			}
			if x == "Contraseñas" {
				br.Password = true
			}
			br.Data = append(br.Data, x)
		}
		switch strings.ToLower(d.PasswordRk) {
		case "plaintext":
			br.PwRisk, br.Password = "en texto claro", true
		case "easytocrack":
			br.PwRisk = "fáciles de descifrar"
		case "hardtocrack":
			br.PwRisk = "cifradas (difíciles de descifrar)"
		}
		out.Breaches = append(out.Breaches, br)
	}
	return out
}

// ---------- CISA KEV (fallos explotados) ----------

type KEVEntry struct {
	CVE     string `json:"cveID"`
	Vendor  string `json:"vendorProject"`
	Product string `json:"product"`
	Name    string `json:"vulnerabilityName"`
	Added   string `json:"dateAdded"`
}

func FetchKEV() ([]KEVEntry, error) {
	b, code, err := httpGet("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("CISA respondió %d", code)
	}
	var v struct {
		Vulnerabilities []KEVEntry `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return v.Vulnerabilities, nil
}
