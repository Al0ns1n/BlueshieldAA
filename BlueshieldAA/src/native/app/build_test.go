package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildSecurity(t *testing.T) {
	js := `{"av":[{"name":"Windows Defender","state":397568}],"defPresent":true,"defEnabled":true,"defRT":true,"defSigAge":9,"defTamper":false,"cfa":0,
"fw":[{"Name":"Domain","Enabled":true},{"Name":"Public","Enabled":false}],"bl":0,"lua":1,"consent":5,"smb1":true,"rdpDeny":0,"rdpNla":0,"guest":false,
"secureBoot":true,"reboot":true,"wdigest":1,"llmnr":null,"ppl":null,"autorun":255,"psv2":"Disabled","lmcompat":5}`
	var s SecInfo
	if err := json.Unmarshal([]byte(js), &s); err != nil {
		t.Fatal(err)
	}
	m := map[string]*Item{}
	for _, it := range BuildSecurity(s) {
		m[it.ID] = it
	}
	expect := map[string]string{"sec:av": "Al día", "sec:sig": "Actualizar", "sec:tamper": "Revisar", "sec:fw:Public": "Vulnerable", "sec:fw:Domain": "Al día",
		"sec:bl": "Revisar", "sec:smb1": "Vulnerable", "sec:rdp": "Vulnerable", "sec:reboot": "Revisar", "hard:wdigest": "Vulnerable", "hard:llmnr": "Revisar",
		"hard:autorun": "Al día", "hard:psv2": "Al día", "hard:lmcompat": "Al día", "sec:uac": "Al día"}
	for id, st := range expect {
		if m[id] == nil {
			t.Errorf("falta %s", id)
			continue
		}
		if m[id].Status != st {
			t.Errorf("%s: %s, esperaba %s", id, m[id].Status, st)
		}
	}
	if m["sec:guest"] != nil {
		t.Error("invitado desactivado no debería salir")
	}
	if m["sec:fw:Public"].Action != "firewall" || m["sec:fw:Public"].Arg != "Public" {
		t.Error("acción del firewall")
	}
}

func TestThirdPartyAV(t *testing.T) {
	var s SecInfo
	json.Unmarshal([]byte(`{"av":[{"name":"ESET Security","state":266240}],"defPresent":true,"defEnabled":false,"defRT":false}`), &s)
	for _, it := range BuildSecurity(s) {
		if it.ID == "sec:av" && (it.Status != "Al día" || !strings.Contains(it.Name, "ESET")) {
			t.Errorf("antivirus de terceros: %+v", it)
		}
		if it.ID == "sec:sig" {
			t.Error("no debería revisar firmas de Defender con otro antivirus")
		}
	}
}

func TestListenersAndIntrusions(t *testing.T) {
	l := BuildListeners([]Listener{{Addr: "0.0.0.0", Port: 445, Proto: "TCP", Proc: "System"}, {Addr: "::", Port: 445, Proto: "TCP", Proc: "System"},
		{Addr: "127.0.0.1", Port: 9000, Proto: "TCP"}, {Addr: "0.0.0.0", Port: 50000, Proto: "UDP"}, {Addr: "0.0.0.0", Port: 7680, Proto: "TCP", Proc: "svchost"}})
	if len(l) != 2 || l[0].Status != "Abierto" || l[1].Status != "Info" {
		t.Errorf("puertos: %+v", l)
	}
	in := BuildIntrusions([]FailedLogon{{IP: "203.0.113.5", User: "admin", Count: 30}, {IP: "203.0.113.5", User: "administrador", Count: 5}, {IP: "-", User: "pepe", Count: 3}, {IP: "198.51.100.1", User: "x", Count: 2}})
	if len(in) != 1 || in[0].Status != "Vulnerable" || in[0].Action != "blockip" || in[0].Arg != "203.0.113.5" {
		t.Errorf("intrusiones: %+v", in)
	}
}

func TestChanges(t *testing.T) {
	now := []PersistEntry{{Kind: "run", Name: "OneDrive", Cmd: `C:\Program Files\OneDrive.exe`}, {Kind: "task", Name: `\Updater`, Cmd: `powershell -enc AAAA`}, {Kind: "admin", Name: `PC\hacker`, Cmd: "S-1-5-21-1"}}
	if BuildChanges(now, nil) != nil {
		t.Error("sin foto previa no debe avisar")
	}
	base := map[string]bool{persistKey(now[0]): true}
	l := BuildChanges(now, base)
	if len(l) != 2 || l[0].Status != "Vulnerable" || l[1].Status != "Vulnerable" {
		t.Errorf("cambios: %+v", l)
	}
}

func TestClassifyConn(t *testing.T) {
	c := Conn{Proc: "svchost", Path: `C:\Users\ana\AppData\Roaming\svchost.exe`}
	ClassifyConn(&c, "8.8.8.8", 443)
	if c.Risk != "Alerta" || c.Scope != "Internet" || c.Svc != "HTTPS" {
		t.Errorf("svchost falso: %+v", c)
	}
	c = Conn{Proc: "chrome", Path: `C:\Program Files\Google\Chrome\Application\chrome.exe`}
	ClassifyConn(&c, "142.250.1.1", 443)
	if c.Risk != "" {
		t.Errorf("chrome normal: %+v", c)
	}
	c = Conn{Proc: "x", Path: `C:\Users\ana\AppData\Local\Temp\x.exe`}
	ClassifyConn(&c, "192.168.1.10", 445)
	if c.Risk != "" || c.Scope != "LAN" {
		t.Errorf("temp a LAN: %+v", c)
	}
}

func TestReport(t *testing.T) {
	items := []*Item{{Category: "Programas", Name: "App <A>", Status: "Actualizar", Current: "1", Available: "2"}, {Category: "Seguridad", Name: "Firewall", Status: "Al día", Current: "-", Available: "-"}}
	h := BuildReportHTML(items, "PC1", true)
	if !strings.Contains(h, "App &lt;A&gt;") || !strings.Contains(h, "ENS") || !strings.Contains(h, "1 pendiente") {
		t.Error("informe")
	}
}

func TestJunkAndEvents(t *testing.T) {
	j := BuildJunk([]JunkDir{{ID: "usertemp", Bytes: 900 << 20}, {ID: "thumbs", Bytes: 10 << 20}, {ID: "recycle", Bytes: 100}})
	if len(j) != 2 || j[0].Status != "Limpiable" || j[1].Status != "Info" {
		t.Errorf("limpieza: %+v", j)
	}
	e := BuildEvents([]EvGroup{{Kind: "power41", Count: 2, Last: "2026-11-20 10:00"}, {Kind: "appcrash", Count: 3}})
	if len(e) != 2 || e[0].Status != "Vulnerable" || e[1].Status != "Info" {
		t.Errorf("eventos: %+v", e)
	}
}
