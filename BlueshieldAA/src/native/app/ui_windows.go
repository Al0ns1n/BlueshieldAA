//go:build windows

package main

// Funciones que la interfaz llama (window.caXxx). Las lentas se lanzan en segundo plano
// y la interfaz se entera por caState.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const later = "Esta parte vuelve en una próxima versión 4.x."

func (a *App) bind() {
	w, e, st := a.W, a.E, a.St
	b := func(name string, f any) {
		if err := w.Bind(name, f); err != nil {
			e.Log("err", "No se pudo registrar %s: %v", name, err)
		}
	}

	// ---- ventana ----
	b("winDrag", func() { a.drag(htCaption) })
	b("winResize", func(edge string) {
		if ht, ok := edgeHT[edge]; ok {
			a.drag(ht)
		}
	})
	b("winMax", func() bool {
		ch := make(chan bool, 1)
		w.Dispatch(func() { ch <- a.toggleMax() })
		return <-ch
	})
	b("winMin", func() { w.Dispatch(func() { pShowWindow.Call(a.hwnd, 6) }) })
	b("winClose", func() { a.close(false) })
	b("winForceClose", func() { a.close(true) })

	// ---- arranque y estado ----
	b("caInit", func() map[string]any {
		sv, saved := st.LoadItems()
		fresh := saved && time.Since(sv.When) < 15*time.Minute
		var out map[string]any
		st.WithCfg(func(c *Config) {
			out = map[string]any{
				"version": AppVersion, "computer": computerName(), "admin": isAdmin(), "portable": a.portable, "company": false,
				"settings": c.Settings, "projects": nz(c.Projects), "domains": nz(c.Domains), "backups": nz(c.Backups),
				"updateURL": c.UpdateURL, "server": c.Server, "theme": c.Theme, "saved": saved, "fresh": fresh,
			}
		})
		if crash := a.lastCrash(); crash != "" {
			out["crash"] = crash
		}
		return out
	})
	b("caState", func(ver, logNext int) StateOut { return e.State(ver, logNext) })
	b("caScan", func() { go e.Scan(false) })
	b("caStartupScan", func() {
		sv, saved := st.LoadItems()
		age := time.Duration(1 << 62)
		if saved {
			age = time.Since(sv.When)
		}
		go e.StartupRefresh(age, 30*time.Minute, 6*time.Hour)
	})
	b("caSearchUpdates", func() { go e.Refresh("programas", "Windows Update") })
	b("caPentest", func(cfg, apps, network bool) { go e.Scan(false) })
	b("caSetChecked", func(id string, v bool) { e.SetChecked(id, v) })
	b("caRecommend", func(page string) { e.Recommend(page) })
	b("caUncheck", func() { e.Uncheck() })
	b("caPlan", func(ids []string) Plan { return e.Plan(ids) })
	b("caRun", func(ids []string) { go e.Run(ids) })
	b("caAlt", func(id string) string { return e.RunAlt(id) })
	b("caDismiss", func(id string) { e.Dismiss(id) })
	b("caDismissedCount", func() int { return e.DismissedCount() })
	b("caResetDismissed", func() { e.ResetDismissed() })
	b("caExclude", func(id string) { e.Exclude(id) })
	b("caRemoveExclusion", func(id string) { e.RemoveExclusion(id) })
	b("caHistory", func() []HistOut { return e.History() })
	b("caScoreHistory", func() []ScorePoint {
		st.mu.Lock()
		defer st.mu.Unlock()
		return append([]ScorePoint{}, st.Pts...)
	})
	b("caUndo", func(idx int) string {
		h := e.History()
		if idx < 0 || idx >= len(h) || !h[idx].CanUndo {
			return "No se puede deshacer esta actualización."
		}
		x := h[idx]
		wg := wingetPath()
		if wg == "" {
			return "No se encuentra winget."
		}
		out, code, err := runExe(30*time.Minute, wg, "install", "--id", x.WingetID, "--exact", "--version", x.From, "--force", "--silent", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity")
		if err != nil || code != 0 {
			return "No se pudo volver a la versión " + x.From + ": " + wingetErr(out)
		}
		st.mu.Lock()
		st.Hist[idx].Undone = true
		_ = writeJSON(st.Path("historial.json"), st.Hist)
		st.mu.Unlock()
		st.UpdateCfg(func(c *Config) { c.Excluded[x.WingetID] = true })
		e.Log("ok", "✔ %s devuelto a la versión %s", x.Name, x.From)
		return ""
	})
	b("caDisk", func() map[string]uint64 {
		free, tot := diskFree(os.Getenv("SystemDrive") + `\`)
		return map[string]uint64{"free": free, "total": tot}
	})

	// ---- ajustes ----
	b("caSetTheme", func(theme string, dark bool) {
		st.UpdateCfg(func(c *Config) { c.Theme = theme })
	})
	b("caSaveSettings", func(s Settings) { st.UpdateCfg(func(c *Config) { c.Settings = s }) })
	b("caSaveLists", func(domains, backups []string, url string) {
		st.UpdateCfg(func(c *Config) { c.Domains, c.Backups, c.UpdateURL = domains, backups, url })
	})
	b("caAddProject", func() []string {
		p := pickFolder(a.hwnd, "Elige la carpeta del proyecto")
		var out []string
		st.UpdateCfg(func(c *Config) {
			if p != "" && !contains(c.Projects, p) {
				c.Projects = append(c.Projects, p)
			}
			out = nz(append([]string(nil), c.Projects...))
		})
		return out
	})
	b("caRemoveProject", func(p string) []string {
		var out []string
		st.UpdateCfg(func(c *Config) { c.Projects = remove(c.Projects, p); out = nz(append([]string(nil), c.Projects...)) })
		return out
	})
	b("caPickFolder", func(title string) string { return pickFolder(a.hwnd, title) })
	b("caSaveServer", func(v ServerCfg, secret string) string {
		st.UpdateCfg(func(c *Config) { v.HasSecret = c.Server.HasSecret || secret != ""; c.Server = v })
		if v.Enabled {
			return "Guardado. La vigilancia de servidores y Keycloak vuelve en una próxima versión 4.x."
		}
		return ""
	})
	b("caTestServers", func() []map[string]string { return []map[string]string{} })
	b("caCveStatus", func() map[string]any {
		has := false
		st.WithCfg(func(c *Config) { has = c.NvdKey != "" })
		return map[string]any{"hasKey": has, "info": "En la versión 4.0 los programas se cruzan con la lista de fallos explotados de CISA (KEV), que no necesita clave."}
	})
	b("caSetNvdKey", func(k string) { st.UpdateCfg(func(c *Config) { c.NvdKey = strings.TrimSpace(k) }) })
	b("caCheckUpdate", func() map[string]any { return map[string]any{"available": false} })
	b("caApplyUpdate", func() string { return "No hay ninguna versión nueva." })

	// ---- enlaces, carpetas e informes ----
	b("caOpenURL", func(u string) { openURL(u) })
	b("caReveal", func(p string) { reveal(p) })
	b("caOpenLogs", func() { a.writeLog(); shellOpen(st.Dir, "") })
	b("caExportTXT", func() string { return a.exportTXT() })
	b("caPentestReport", func() string { return a.reportHTML(false) })
	b("caCompliance", func() string { return a.reportHTML(true) })

	// ---- filtraciones ----
	b("caPwStrength", func(pw string) PwStrength { return PasswordStrength(pw) })
	b("caPwnedPassword", func(pw string) PwnedOut { return PwnedPassword(pw) })
	b("caBreachedEmail", func(m string) BreachOut { return BreachedEmail(m) })

	// ---- analizar archivo ----
	b("faPick", func() {
		p := pickFile(a.hwnd, "Elige el archivo que quieres analizar")
		if p == "" {
			return
		}
		js, _ := json.Marshal(p)
		w.Dispatch(func() { w.Eval("faAnalyze(" + string(js) + ")") })
	})
	b("caFAEngine", func() map[string]string { return map[string]string{"version": FAEngineVersion} })
	b("caAnalyzeFile", func(path string) *FAResult {
		r := analyzeFile(path)
		a.lastFA = r
		return r
	})
	b("caQuarantine", func(p string) string {
		var r *FAResult
		if a.lastFA != nil && strings.EqualFold(a.lastFA.Path, p) {
			r = a.lastFA
		}
		m := Quarantine(st, p, r)
		if m == "" {
			e.Log("ok", "✔ %s aislado en la cuarentena", filepath.Base(p))
		}
		return m
	})
	b("caQuarantineList", func() []QItem { return QuarantineList(st) })

	// ---- entorno aislado (Windows Sandbox) ----
	b("caSbStatus", func() SBStatus { return SandboxStatus() })
	b("caSbEnable", func() string { return SandboxEnable(e) })
	b("caSbRun", func(path string, secs int) string { return SandboxRun(a, path, secs) })
	b("caSbPoll", func(id string) SBPoll { return SandboxPoll(id) })
	b("caSbShot", func(id, name string) string { return SandboxShot(id, name) })
	b("caSbStop", func(id string) { SandboxStop(id) })

	// ---- explorador de espacio (Mantenimiento → Limpieza) ----
	b("caDrives", func() []DriveInfo { return Drives() })
	b("caDiskScan", func(root string) string { return DiskStart(root) })
	b("caDiskCancel", func() { diskScan.Cancel() })
	b("caDiskPoll", func() map[string]any { return map[string]any{"scan": diskScan.Progress(), "del": DelStatus()} })
	b("caDiskView", func(path string) map[string]any {
		v, ok := diskScan.View(path)
		if !ok {
			return map[string]any{"ok": false}
		}
		return map[string]any{"ok": true, "view": v}
	})
	b("caDiskTop", func() []DEntry { return diskScan.TopFiles(100) })
	b("caDiskRecs", func() []DEntry { return diskScan.Recommend() })
	b("caDiskDelete", func(paths []string, toBin bool) string { return DiskDelete(e, paths, toBin) })
	b("caDiskAction", func(name string) string { return DiskAction(e, name) })

	// ---- aplicaciones, hardware y cuentas ----
	b("caApps", func() []InstalledApp { return InstalledApps(e) })
	b("caAppUninstall", func(id string) string { return AppUninstall(e, id) })
	b("caAppReveal", func(id string) string { return AppReveal(id) })
	b("caDevices", func() map[string]any { return Devices() })
	b("caHardware", func() map[string]any { return HardwareInfo() })
	b("caDevManager", func() { shellOpen("devmgmt.msc", "") })
	b("caAccounts", func() map[string]any { return MyAccounts() })
	b("caLogons", func() map[string]any { return Logons() })

	// ---- procesos (Eventos → Procesos) ----
	b("caProcesses", func() ProcOut { return Processes() })
	b("caProcKill", func(pid int, name string) string { return ProcKill(e, pid, name) })
	b("caQuarantineRestore", func(id string) string { return QuarantineRestore(st, id) })
	b("caQuarantineDelete", func(id string) string { return QuarantineDelete(st, id) })

	// ---- red y diagnóstico ----
	b("caTraffic", func() TrafficOut { return Traffic() })
	b("caDiag", func(rangeSec float64, since float64) map[string]any { return Diag(int(rangeSec), int64(since)) })

	// ---- anti-ransomware (guardián + modo contención) ----
	a.bindGuard(b)

	// ---- Panel de empresa: aún no en la 4.x ----
	b("caOpenPanel", func() {
		w.Dispatch(func() { w.Eval(`toast(` + jsStr("El Panel de empresa vuelve en una próxima versión 4.x.") + `)`) })
	})
	b("pnFleet", func() map[string]any { return map[string]any{"shared": "", "fleet": []any{}} })
	b("pnPolicy", func() map[string]any { return map[string]any{} })
	for _, n := range []string{"pnPickShared", "pnSavePolicy", "pnCommand", "pnCommandBatch", "pnTestWebhook", "pnExportCSV", "pnExportHTML", "pnCompliance", "pnPentestReport"} {
		b(n, func(args ...any) string { return "" })
	}
}

func jsStr(s string) string { b, _ := json.Marshal(s); return string(b) }

func nz(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func remove(l []string, s string) []string {
	out := []string{}
	for _, x := range l {
		if !strings.EqualFold(x, s) {
			out = append(out, x)
		}
	}
	return out
}

// analyzeFile: análisis estático + firma + origen + reputación + Defender.
func analyzeFile(path string) *FAResult {
	data, size, err := ReadForAnalysis(path)
	if err != nil {
		return &FAResult{Err: "No se puede leer el archivo: " + err.Error(), Path: path}
	}
	r := AnalyzeBytes(path, data, size)
	r.Path = path
	// firma y origen con funciones nativas (sin PowerShell)
	type sig struct{ Status, Signer, Zone string }
	s := sig{}
	if r.Kind == "pe" || r.Kind == "script" || r.Kind == "office-ole" {
		m := FileMeta(path)
		switch m.Signed {
		case "Firmado", "Microsoft":
			s.Status, s.Signer = "Valid", m.Signer
		case "Sin firmar":
			s.Status = "NotSigned"
		case "Firma no válida":
			s.Status = "HashMismatch"
		}
	}
	if z, err := os.ReadFile(path + ":Zone.Identifier"); err == nil {
		s.Zone = string(z)
	}
	switch s.Status {
	case "Valid":
		r.Signature, r.Signer = "Válida", s.Signer
	case "NotSigned", "":
		if r.Kind == "pe" || r.Kind == "script" {
			r.Signature = "Sin firmar"
		}
	case "UnknownError", "NotSupportedFileFormat":
	default:
		r.Signature = s.Status
		if r.Kind == "pe" {
			r.add("danger", 30, "Firma digital no válida", "El archivo está firmado pero la firma no es válida ("+s.Status+"): puede haber sido modificado.")
		}
	}
	if s.Zone != "" {
		r.Origin = zoneOrigin(s.Zone)
		if strings.Contains(s.Zone, "ZoneId=3") || strings.Contains(s.Zone, "ZoneId=4") {
			if r.Kind == "pe" && r.Signature != "Válida" || r.Kind == "script" || r.Kind == "lnk" || r.Kind == "hta" {
				r.add("warn", 10, "Viene de Internet y no está firmado", "Se descargó de Internet (o llegó en un correo) y no tiene una firma digital válida que diga quién lo ha hecho.")
			}
		}
	}
	if r.Signature == "Válida" {
		r.add("ok", -15, "Firmado por "+r.Signer, "La firma digital es válida y el archivo no se ha modificado desde que se firmó.")
	}
	Reputation(r)
	r.Defender = defenderScan(path)
	if strings.HasPrefix(r.Defender, "AMENAZA") {
		r.add("danger", 50, "Microsoft Defender lo detecta", r.Defender)
	}
	r.Engine = "Motor BlueShieldAA " + FAEngineVersion + " · Microsoft Defender (segunda opinión)"
	r.finish()
	return r
}

func zoneOrigin(z string) string {
	o := map[string]string{"ZoneId=0": "Este equipo", "ZoneId=1": "Red local", "ZoneId=2": "Sitio de confianza", "ZoneId=3": "Internet", "ZoneId=4": "Sitio restringido"}
	res := "Desconocido"
	for k, v := range o {
		if strings.Contains(z, k) {
			res = v
		}
	}
	for _, ln := range strings.Split(z, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "HostUrl=") && !strings.Contains(ln, "about:internet") {
			res += " (" + strings.TrimPrefix(ln, "HostUrl=") + ")"
			break
		}
		if strings.HasPrefix(ln, "ReferrerUrl=") {
			res += " (" + strings.TrimPrefix(ln, "ReferrerUrl=") + ")"
		}
	}
	return res
}

func defenderScan(path string) string {
	mp := filepath.Join(os.Getenv("ProgramFiles"), "Windows Defender", "MpCmdRun.exe")
	if _, err := os.Stat(mp); err != nil {
		return "No disponible"
	}
	out, code, err := runExe(3*time.Minute, mp, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation")
	if err != nil {
		return "No se pudo consultar"
	}
	if code == 2 {
		for _, ln := range strings.Split(out, "\n") {
			ln = strings.TrimSpace(ln)
			if strings.HasPrefix(ln, "Threat ") || strings.Contains(ln, "Threat  ") {
				if i := strings.Index(ln, ":"); i > 0 {
					return "AMENAZA: " + strings.TrimSpace(ln[i+1:])
				}
			}
		}
		return "AMENAZA detectada"
	}
	if code == 0 {
		return "Sin amenazas"
	}
	return fmt.Sprintf("No se pudo analizar (código %d)", code)
}

// ---------- informes ----------

// docsDir: Documentos públicos, para que el usuario del escritorio vea los informes aunque
// el programa se haya abierto con otra cuenta (.adm).
func docsDir() string {
	pub := os.Getenv("PUBLIC")
	if pub == "" {
		pub = `C:\Users\Public`
	}
	d := filepath.Join(pub, "Documents", AppName)
	if os.MkdirAll(d, 0o755) != nil {
		d = filepath.Join(app.St.Dir, "informes")
		os.MkdirAll(d, 0o755)
	}
	return d
}

func (a *App) writeLog() {
	s := a.E.State(-1, 0)
	var sb strings.Builder
	for _, l := range s.Logs {
		sb.WriteString(fmt.Sprintf("[%s] %s %s\r\n", l.T, strings.ToUpper(l.L), l.M))
	}
	_ = os.WriteFile(a.St.Path("registro.txt"), []byte(sb.String()), 0o644)
}

func (a *App) exportTXT() string {
	items := a.E.Items()
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Informe de BlueShieldAA %s\r\nEquipo: %s\r\nFecha: %s\r\nPuntuación: %d de 100\r\n\r\n", AppVersion, computerName(), time.Now().Format("02/01/2006 15:04"), Score(items)))
	cats := map[string][]*Item{}
	order := []string{}
	for _, it := range items {
		if _, ok := cats[it.Category]; !ok {
			order = append(order, it.Category)
		}
		cats[it.Category] = append(cats[it.Category], it)
	}
	sort.Strings(order)
	for _, c := range order {
		sb.WriteString("== " + c + " ==\r\n")
		for _, it := range cats[c] {
			v := ""
			if it.Current != "-" {
				v = " [" + it.Current + ternary(it.Available != "-", " → "+it.Available, "") + "]"
			}
			sb.WriteString(fmt.Sprintf("  %-12s %s%s\r\n", it.Status, it.Name, v))
		}
		sb.WriteString("\r\n")
	}
	p := filepath.Join(docsDir(), "BlueShieldAA-"+computerName()+"-"+time.Now().Format("2006-01-02_1504")+".txt")
	if os.WriteFile(p, []byte(sb.String()), 0o644) != nil {
		return ""
	}
	return p
}

func (a *App) reportHTML(compliance bool) string {
	html := BuildReportHTML(a.E.Items(), computerName(), compliance)
	name := ternary(compliance, "Cumplimiento", "Seguridad")
	p := filepath.Join(docsDir(), "Informe-"+name+"-"+computerName()+"-"+time.Now().Format("2006-01-02_1504")+".html")
	if os.WriteFile(p, []byte(html), 0o644) != nil {
		return ""
	}
	shellOpen(p, "")
	return p
}
