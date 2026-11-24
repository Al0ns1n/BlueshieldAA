//go:build windows

package main

// Guardián anti-ransomware (BlueShieldAA.exe --guardian, tarea programada como SYSTEM).
// Vigila los documentos trampa y las órdenes que el ransomware lanza antes de cifrar y, si
// detecta un ataque, pone el equipo en modo contención: congela al culpable, deja ejecutar
// solo Windows, corta la red y para los servicios que comparten el equipo. Todo solo en ESTE
// equipo: nunca toca carpetas de red, OneDrive ni otros equipos.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	guardTask    = `\BlueShieldAA\Guardian`
	fwRuleOut    = "BlueShieldAA-Contencion-Salida"
	fwRuleIn     = "BlueShieldAA-Contencion-Entrada"
	guardMutex   = `Global\BlueShieldAA-Guardian4`
	guardStaleAt = 12 * time.Second
)

var (
	ntdll                 = windows.NewLazySystemDLL("ntdll.dll")
	pNtSuspendProcess     = ntdll.NewProc("NtSuspendProcess")
	pGetProcessIoCounters = kernel32.NewProc("GetProcessIoCounters")
	pWTSSendMessageW      = wtsapi32.NewProc("WTSSendMessageW")
)

// ---------- archivos del guardián (en ProgramData\BlueShieldAA\v4) ----------

type guardFiles struct{ dir string }

func (g guardFiles) p(n string) string { return filepath.Join(g.dir, n) }

func (g guardFiles) cfg() GuardConfig {
	c := DefaultGuardConfig()
	_ = readJSON(g.p("guardian.json"), &c)
	if c.Mode != "contener" {
		c.Mode = "simulacro"
	}
	return c
}
func (g guardFiles) saveCfg(c GuardConfig) error { return writeJSON(g.p("guardian.json"), c) }

func (g guardFiles) rt() GuardRuntime {
	var r GuardRuntime
	_ = readJSON(g.p("guardian-estado.json"), &r)
	return r
}
func (g guardFiles) saveRt(r GuardRuntime) { _ = writeJSON(g.p("guardian-estado.json"), r) }

func (g guardFiles) cont() Containment {
	var c Containment
	_ = readJSON(g.p("contencion.json"), &c)
	return c
}
func (g guardFiles) saveCont(c Containment) { _ = writeJSON(g.p("contencion.json"), c) }

func (g guardFiles) incidents() []GuardIncident {
	var l []GuardIncident
	_ = readJSON(g.p("guardian-incidentes.json"), &l)
	return l
}
func (g guardFiles) saveIncidents(l []GuardIncident) {
	if len(l) > 60 {
		l = l[:60]
	}
	_ = writeJSON(g.p("guardian-incidentes.json"), l)
}
func (g guardFiles) addIncident(i GuardIncident) {
	g.saveIncidents(append([]GuardIncident{i}, g.incidents()...))
}
func (g guardFiles) updateIncident(id string, f func(i *GuardIncident)) {
	l := g.incidents()
	for k := range l {
		if l[k].ID == id {
			f(&l[k])
		}
	}
	g.saveIncidents(l)
}

func (g guardFiles) scan() ScanState {
	var s ScanState
	_ = readJSON(g.p("guardian-analisis.json"), &s)
	return s
}

var glogMu sync.Mutex

func (g guardFiles) log(format string, a ...any) {
	glogMu.Lock()
	defer glogMu.Unlock()
	p := g.p("guardian.log")
	if fi, err := os.Stat(p); err == nil && fi.Size() > 1<<20 {
		_ = os.Rename(p, p+".1")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	fmt.Fprintf(f, "%s  %s\r\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, a...))
	f.Close()
}

func (g guardFiles) order(o GuardOrder) error {
	o.When = time.Now()
	return writeJSON(g.p(filepath.Join("ordenes", fmt.Sprintf("%d-%s.json", time.Now().UnixNano(), o.Cmd))), o)
}

func (g guardFiles) running() bool {
	r := g.rt()
	return !r.Beat.IsZero() && time.Since(r.Beat) < guardStaleAt
}

// ---------- procesos ----------

type gProc struct {
	PID, PPID int
	Name      string
	Path      string
	Start     time.Time
	Write     uint64
}

type ioCounters struct{ rOps, wOps, oOps, rBytes, wBytes, oBytes uint64 }

func snapProcs(withPath bool) []gProc {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []gProc
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		p := gProc{PID: int(e.ProcessID), PPID: int(e.ParentProcessID), Name: windows.UTF16ToString(e.ExeFile[:])}
		if withPath && p.PID > 4 {
			if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, e.ProcessID); err == nil {
				buf := make([]uint16, 1024)
				n := uint32(len(buf))
				if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
					p.Path = windows.UTF16ToString(buf[:n])
				}
				var c, x, k, u windows.Filetime
				if windows.GetProcessTimes(h, &c, &x, &k, &u) == nil {
					p.Start = time.Unix(0, c.Nanoseconds())
				}
				var io ioCounters
				if r, _, _ := pGetProcessIoCounters.Call(uintptr(h), uintptr(unsafe.Pointer(&io))); r != 0 {
					p.Write = io.wBytes
				}
				windows.CloseHandle(h)
			}
		}
		out = append(out, p)
	}
	return out
}

func cmdLineOf(pid int) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	return procCmdLine(h)
}

func suspendPID(pid int) bool {
	h, err := windows.OpenProcess(0x0800 /*PROCESS_SUSPEND_RESUME*/, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	r, _, _ := pNtSuspendProcess.Call(uintptr(h))
	return r == 0
}

func isOurPath(path, installDir string) bool {
	if path == "" || installDir == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(path), strings.ToLower(installDir)+`\`)
}

// ---------- aviso en pantalla a todas las sesiones ----------

func alertSessions(title, msg string) {
	var info *windows.WTS_SESSION_INFO
	var n uint32
	if windows.WTSEnumerateSessions(0, 0, 1, &info, &n) != nil {
		return
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	sessions := unsafe.Slice(info, n)
	t := utf16.Encode([]rune(title))
	m := utf16.Encode([]rune(msg))
	t = append(t, 0)
	m = append(m, 0)
	for _, s := range sessions {
		if s.State != windows.WTSActive {
			continue
		}
		var resp uint32
		pWTSSendMessageW.Call(0, uintptr(s.SessionID), uintptr(unsafe.Pointer(&t[0])), uintptr((len(t)-1)*2),
			uintptr(unsafe.Pointer(&m[0])), uintptr((len(m)-1)*2), 0x10|0x1000|0x40000 /*ICONERROR|SYSTEMMODAL|TOPMOST*/, 0, uintptr(unsafe.Pointer(&resp)), 0)
	}
}

// ---------- documentos trampa ----------

func guardFolderList(cfg GuardConfig) (list []string, errs []string) {
	seen := map[string]bool{}
	add := func(p string, custom bool) {
		k := strings.ToLower(filepath.Clean(p))
		if seen[k] {
			return
		}
		fi, err := os.Lstat(p)
		if err != nil || !fi.IsDir() {
			if custom {
				errs = append(errs, "No existe la carpeta "+p)
			}
			return
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return
		}
		if ok, why := FolderAllowed(p); !ok {
			if custom {
				errs = append(errs, p+": "+why)
			}
			return
		}
		seen[k] = true
		list = append(list, p)
	}
	sysDrive := strings.ToUpper(os.Getenv("SystemDrive"))
	if sysDrive == "" {
		sysDrive = "C:"
	}
	users := filepath.Join(sysDrive+`\`, "Users")
	if es, err := os.ReadDir(users); err == nil {
		for _, e := range es {
			n := strings.ToLower(e.Name())
			if !e.IsDir() || n == "public" || n == "default" || n == "default user" || n == "all users" || strings.HasPrefix(n, "defaultuser") || strings.Contains(n, ".adm") {
				continue
			}
			home := filepath.Join(users, e.Name())
			if _, err := os.Stat(filepath.Join(home, "NTUSER.DAT")); err != nil {
				continue
			}
			for _, sub := range []string{"Desktop", "Documents", "Pictures", "Downloads"} {
				add(filepath.Join(home, sub), false)
			}
		}
	}
	add(filepath.Join(users, "Public", "Documents"), false)
	for l := 'D'; l <= 'Z'; l++ {
		root := string(l) + `:\`
		if strings.EqualFold(string(l)+":", sysDrive) {
			continue
		}
		rp, _ := windows.UTF16PtrFromString(root)
		if windows.GetDriveType(rp) == windows.DRIVE_FIXED {
			add(root, false)
		}
	}
	for _, c := range cfg.Custom {
		add(c, true)
	}
	return
}

func writeDecoy(path, marker string) (Decoy, error) {
	p16, _ := windows.UTF16PtrFromString(path)
	_ = windows.SetFileAttributes(p16, windows.FILE_ATTRIBUTE_NORMAL)
	if err := os.WriteFile(path, DecoyBytes(filepath.Base(path), marker), 0o644); err != nil {
		return Decoy{}, err
	}
	_ = windows.SetFileAttributes(p16, windows.FILE_ATTRIBUTE_HIDDEN)
	fi, err := os.Stat(path)
	if err != nil {
		return Decoy{}, err
	}
	return Decoy{Path: path, Size: fi.Size(), MTime: fi.ModTime().Unix()}, nil
}

func removeDecoys(l []Decoy) {
	for _, d := range l {
		p16, _ := windows.UTF16PtrFromString(d.Path)
		_ = windows.SetFileAttributes(p16, windows.FILE_ATTRIBUTE_NORMAL)
		_ = os.Remove(d.Path)
	}
}

// seed pone o repone los señuelos. Conserva los que siguen intactos.
func seedDecoys(cfg GuardConfig, rt *GuardRuntime) {
	folders, errs := guardFolderList(cfg)
	keep := map[string]Decoy{}
	for _, d := range rt.Decoys {
		keep[strings.ToLower(d.Path)] = d
	}
	in := map[string]bool{}
	var out []Decoy
	rt.Folders = nil
	for _, f := range folders {
		n := 0
		for _, name := range decoyNames {
			p := filepath.Join(f, name)
			in[strings.ToLower(p)] = true
			if d, ok := keep[strings.ToLower(p)]; ok && len(CheckDecoys([]Decoy{d})) == 0 {
				out = append(out, d)
				n++
				continue
			}
			d, err := writeDecoy(p, cfg.Marker)
			if err != nil {
				errs = append(errs, "No se pudo poner un señuelo en "+f+": "+err.Error())
				break
			}
			out = append(out, d)
			n++
		}
		rt.Folders = append(rt.Folders, GuardFolder{Path: f, N: n})
	}
	var gone []Decoy
	for k, d := range keep {
		if !in[k] {
			gone = append(gone, d)
		}
	}
	removeDecoys(gone)
	rt.Decoys, rt.Errors = out, errs
}

// ---------- contención ----------

func netsh(args ...string) (string, error) {
	out, code, err := runExe(60*time.Second, filepath.Join(sysDir(), "netsh.exe"), args...)
	if err == nil && code != 0 {
		err = fmt.Errorf("netsh terminó con código %d", code)
	}
	return out, err
}

func isolateNetwork(g guardFiles, c *Containment) {
	bk := g.p("cortafuegos-antes.wfw")
	if !c.Isolated {
		_ = os.Remove(bk)
		if _, err := netsh("advfirewall", "export", bk); err == nil {
			c.FwBackup = bk
		} else {
			c.Errors = append(c.Errors, "No se pudo guardar la configuración del cortafuegos: "+err.Error())
		}
	}
	_, _ = netsh("advfirewall", "set", "allprofiles", "state", "on")
	for _, r := range [][2]string{{fwRuleOut, "out"}, {fwRuleIn, "in"}} {
		_, _ = netsh("advfirewall", "firewall", "delete", "rule", "name="+r[0])
		if _, err := netsh("advfirewall", "firewall", "add", "rule", "name="+r[0], "dir="+r[1], "action=block", "enable=yes", "profile=any", "remoteip=any"); err != nil {
			c.Errors = append(c.Errors, "No se pudo bloquear la red ("+r[1]+"): "+err.Error())
			continue
		}
		c.Isolated = true
	}
}

func restoreNetwork(g guardFiles, c *Containment) []string {
	var errs []string
	for _, r := range []string{fwRuleOut, fwRuleIn} {
		_, _ = netsh("advfirewall", "firewall", "delete", "rule", "name="+r)
	}
	if c.FwBackup != "" {
		if _, err := os.Stat(c.FwBackup); err == nil {
			if _, err := netsh("advfirewall", "import", c.FwBackup); err != nil {
				errs = append(errs, "No se pudo restaurar el cortafuegos tal cual estaba (se han quitado los bloqueos): "+err.Error())
			}
		}
	}
	c.Isolated = false
	return errs
}

// servicesToStop: lista de servicios a parar (se usa también en simulacro).
func servicesToStop() (out []SvcState, why map[string]string) {
	why = map[string]string{}
	m, err := mgr.Connect()
	if err != nil {
		return nil, why
	}
	defer m.Disconnect()
	names, _ := m.ListServices()
	sysRoot := os.Getenv("SystemRoot")
	for _, n := range names {
		s, err := m.OpenService(n)
		if err != nil {
			continue
		}
		st, err1 := s.Query()
		cf, err2 := s.Config()
		s.Close()
		if err1 != nil || err2 != nil {
			continue
		}
		running := st.State == svc.Running || st.State == svc.StartPending
		if !running && cf.StartType != mgr.StartAutomatic {
			continue
		}
		if cf.StartType == mgr.StartDisabled && !running {
			continue
		}
		exe := ServiceExe(cf.BinaryPathName, sysRoot)
		meta := FileMeta(exe)
		w := MustStopService(n, meta.Signed, meta.Company)
		if w == "" || isOurPath(exe, filepath.Dir(selfExe())) {
			continue
		}
		why[n] = w
		out = append(out, SvcState{Name: n, Display: cf.DisplayName, StartType: cf.StartType, Running: running})
	}
	return
}

func stopServices(g guardFiles, c *Containment) {
	list, _ := servicesToStop()
	m, err := mgr.Connect()
	if err != nil {
		c.Errors = append(c.Errors, "No se pudo abrir el administrador de servicios: "+err.Error())
		return
	}
	defer m.Disconnect()
	done := map[string]bool{}
	for _, s := range c.Services {
		done[strings.ToLower(s.Name)] = true
	}
	var stop func(name string, rec SvcState, depth int)
	stop = func(name string, rec SvcState, depth int) {
		if done[strings.ToLower(name)] || depth > 4 {
			return
		}
		s, err := m.OpenService(name)
		if err != nil {
			return
		}
		defer s.Close()
		if rec.Name == "" { // servicio que depende de otro: se apunta para devolverlo igual
			cf, _ := s.Config()
			st, _ := s.Query()
			rec = SvcState{Name: name, Display: cf.DisplayName, StartType: cf.StartType, Running: st.State == svc.Running}
		}
		if deps, err := s.ListDependentServices(svc.Active); err == nil {
			for _, d := range deps {
				stop(d, SvcState{}, depth+1)
			}
		}
		done[strings.ToLower(name)] = true
		c.Services = append(c.Services, rec)
		if cf, err := s.Config(); err == nil && cf.StartType != mgr.StartDisabled {
			cf.StartType = mgr.StartDisabled
			_ = s.UpdateConfig(cf)
		}
		if st, err := s.Control(svc.Stop); err == nil {
			for i := 0; i < 40 && st.State != svc.Stopped; i++ {
				time.Sleep(250 * time.Millisecond)
				st, _ = s.Query()
			}
		}
	}
	for _, s := range list {
		stop(s.Name, s, 0)
	}
	g.log("Servicios parados: %d", len(c.Services))
}

func restoreServices(c *Containment) []string {
	var errs []string
	m, err := mgr.Connect()
	if err != nil {
		return []string{"No se pudo abrir el administrador de servicios: " + err.Error()}
	}
	defer m.Disconnect()
	for i := len(c.Services) - 1; i >= 0; i-- {
		r := c.Services[i]
		s, err := m.OpenService(r.Name)
		if err != nil {
			continue
		}
		if cf, err := s.Config(); err == nil {
			cf.StartType = r.StartType
			if err := s.UpdateConfig(cf); err != nil {
				errs = append(errs, "No se pudo devolver el inicio de "+r.Display+": "+err.Error())
			}
		}
		if r.Running {
			if err := s.Start(); err != nil && !strings.Contains(err.Error(), "already") {
				if st, e2 := s.Query(); e2 != nil || st.State != svc.Running {
					errs = append(errs, "No arrancó "+r.Display+" (arráncalo a mano o reinicia)")
				}
			}
		}
		s.Close()
	}
	c.Services = nil
	return errs
}

// releaseContainment quita la contención: red, servicios y bloqueo. La puede ejecutar el
// guardián (orden de la ventana), la ventana si el guardián no responde, o desbloquear.cmd.
func releaseContainment(g guardFiles, by string) []string {
	c := g.cont()
	if !c.Active {
		return nil
	}
	var errs []string
	if c.Isolated {
		errs = append(errs, restoreNetwork(g, &c)...)
	}
	errs = append(errs, restoreServices(&c)...)
	c.Active = false
	c.Released = time.Now()
	c.ReleasedBy = by
	g.saveCont(c)
	if c.Incident != "" {
		g.updateIncident(c.Incident, func(i *GuardIncident) { i.Resolved = true })
	}
	g.log("Contención quitada por %s. %s", by, strings.Join(errs, " | "))
	return errs
}

// ---------- el guardián ----------

type guardian struct {
	g        guardFiles
	st       *Store
	cfg      GuardConfig
	rt       GuardRuntime
	cont     Containment
	seen     map[int]time.Time // PIDs ya revisados para órdenes peligrosas
	io       map[int]uint64
	ioAt     time.Time
	dels     []time.Time
	testPath string
	lock     map[string]string // pid|inicio → "" permitido | motivo
	ours     map[int]time.Time
	self     int
	lastHit  time.Time // último ataque: durante 1 min no se repiten avisos (el cifrado sigue tocando señuelos)
}

func selfExe() string { p, _ := os.Executable(); return p }

func runGuardian() {
	name, _ := windows.UTF16PtrFromString(guardMutex)
	h, err := windows.CreateMutex(nil, false, name)
	if err != nil || windows.GetLastError() == windows.ERROR_ALREADY_EXISTS {
		return // ya hay un guardián en marcha
	}
	defer windows.CloseHandle(h)
	_ = LoadRules(filepath.Join(filepath.Dir(selfExe()), "reglas-analisis.json"))
	dir, portable := dataDir()
	if portable {
		return
	}
	_ = os.MkdirAll(filepath.Join(dir, "ordenes"), 0o755)
	gd := &guardian{g: guardFiles{dir}, st: NewStore(dir), seen: map[int]time.Time{}, io: map[int]uint64{}, lock: map[string]string{}, ours: map[int]time.Time{}, self: os.Getpid()}
	defer func() {
		if r := recover(); r != nil {
			gd.g.log("FALLO del guardián: %v", r)
			os.Exit(2) // la tarea programada lo vuelve a arrancar
		}
	}()
	gd.run()
}

func (gd *guardian) run() {
	g := gd.g
	gd.cfg = g.cfg()
	gd.rt = g.rt()
	gd.cont = g.cont()
	g.log("Guardián %s en marcha (modo %s)", AppVersion, gd.cfg.Mode)
	if gd.cont.Active && !gd.cont.Simulated {
		g.log("El equipo sigue en contención desde %s: se vuelve a aplicar", gd.cont.Since.Format("02/01 15:04"))
		gd.reapply()
	}
	if gd.cfg.Enabled {
		// Señuelos dañados con el guardián parado (p. ej. cifrado en modo seguro o con el equipo apagado)
		if ev := CheckDecoys(gd.rt.Decoys); IsAttack(ev) {
			gd.respond("Documentos trampa dañados mientras el guardián estaba parado", ev, nil)
		}
		seedDecoys(gd.cfg, &gd.rt)
	}
	gd.sampleIO()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	var n int
	lastSeed := time.Now()
	for range tick.C {
		n++
		gd.watchCommands()
		if n%2 == 0 {
			gd.checkDecoys()
			gd.orders()
		}
		if gd.cont.Active && !gd.cont.Simulated && gd.cfg.Lockdown && n%4 == 0 {
			gd.lockdownPass(false)
		}
		if n%8 == 0 {
			gd.sampleIO()
			nc := g.cfg()
			if !nc.Enabled && gd.cfg.Enabled {
				g.log("Protección desactivada: se quitan los señuelos")
				removeDecoys(gd.rt.Decoys)
				gd.rt.Decoys, gd.rt.Folders = nil, nil
			}
			customChanged := strings.Join(nc.Custom, "|") != strings.Join(gd.cfg.Custom, "|")
			gd.cfg = nc
			if gd.cfg.Enabled && (customChanged || time.Since(lastSeed) > 10*time.Minute) {
				seedDecoys(gd.cfg, &gd.rt)
				lastSeed = time.Now()
			}
			gd.rt.Beat, gd.rt.PID, gd.rt.Version = time.Now(), gd.self, AppVersion
			g.saveRt(gd.rt)
			if !gd.cfg.Enabled && !gd.cont.Active {
				g.log("Guardián parado (protección desactivada)")
				return
			}
		}
	}
}

func (gd *guardian) sampleIO() {
	m := map[int]uint64{}
	for _, p := range snapProcs(true) {
		m[p.PID] = p.Write
	}
	gd.io, gd.ioAt = m, time.Now()
}

func (gd *guardian) checkDecoys() {
	if !gd.cfg.Enabled || len(gd.rt.Decoys) == 0 {
		return
	}
	ev := CheckDecoys(gd.rt.Decoys)
	if len(ev) == 0 {
		return
	}
	// ¿es la prueba pedida desde la ventana?
	if gd.testPath != "" && len(ev) == 1 && strings.EqualFold(ev[0].Path, gd.testPath) {
		gd.testPath = ""
		gd.simulate("prueba", "Prueba de la protección pedida desde BlueShieldAA", ev, nil)
		seedDecoys(gd.cfg, &gd.rt)
		return
	}
	now := time.Now()
	for _, e := range ev {
		if e.Kind == "borrado" {
			gd.dels = append(gd.dels, now)
		}
	}
	recent := 0
	for _, t := range gd.dels {
		if now.Sub(t) < time.Minute {
			recent++
		}
	}
	if IsAttack(ev) || recent >= 2 {
		if time.Since(gd.lastHit) < time.Minute {
			gd.g.log("Siguen cambiando señuelos (%d) tras el aviso: %s", len(ev), ev[0].Path)
			if gd.cont.Active && !gd.cont.Simulated && gd.cfg.Lockdown {
				gd.lockdownPass(false)
			}
		} else {
			gd.lastHit = now
			gd.respond("Documentos trampa cifrados, modificados o renombrados", ev, nil)
		}
	} else {
		gd.g.addIncident(GuardIncident{ID: randID(), When: now, Kind: "aviso", Reason: "Se ha borrado un documento trampa (puede haber sido alguien a mano)", Files: []string{ev[0].Path}})
		gd.g.log("Aviso: señuelo borrado %s", ev[0].Path)
	}
	seedDecoys(gd.cfg, &gd.rt)
	gd.g.saveRt(gd.rt)
}

// watchCommands: órdenes que el ransomware lanza antes de cifrar. Se cortan siempre.
func (gd *guardian) watchCommands() {
	procs := snapProcs(false)
	alive := map[int]bool{}
	byPID := map[int]gProc{}
	for _, p := range procs {
		alive[p.PID] = true
		byPID[p.PID] = p
	}
	for pid := range gd.seen {
		if !alive[pid] {
			delete(gd.seen, pid)
		}
	}
	first := len(gd.seen) == 0
	for _, p := range procs {
		if _, ok := gd.seen[p.PID]; ok {
			continue
		}
		gd.seen[p.PID] = time.Now()
		if first || p.PID <= 4 || p.PID == gd.self {
			continue
		}
		cmd := cmdLineOf(p.PID)
		k := RansomCommand(cmd)
		if k == "" {
			continue
		}
		suspendPID(p.PID)
		_ = KillPID(p.PID)
		// ¿quién la ha lanzado? se sube por los padres hasta el primer programa que no es de Microsoft
		var cul []Culprit
		chain := []string{p.Name}
		cur := p
		for i := 0; i < 6; i++ {
			par, ok := byPID[cur.PPID]
			if !ok || par.PID <= 4 {
				break
			}
			path := gd.pathOf(par.PID)
			if isOurPath(path, gd.cfg.InstallDir) {
				break
			}
			meta := FileMeta(path)
			if meta.Signed != "Microsoft" {
				cul = append(cul, Culprit{PID: par.PID, Name: par.Name, Path: path, Cmd: cmdLineOf(par.PID), Why: "lanzó «" + k + "»"})
				break
			}
			if !inList(par.Name, "contencion_bloquear") {
				break // explorer, services…: no se sube más
			}
			chain = append(chain, par.Name)
			cur = par
		}
		ev := []DecoyEvent{{Path: cmd, Kind: "orden"}}
		if len(cul) > 0 {
			gd.respond("Orden típica de ransomware antes de cifrar: «"+k+"» ("+strings.Join(chain, " ← ")+")", ev, cul)
		} else {
			gd.g.addIncident(GuardIncident{ID: randID(), When: time.Now(), Kind: "orden", Reason: "Se ha cortado una orden que borra las copias de seguridad de Windows: «" + k + "». La lanzó un programa de Microsoft (quizá alguien a mano), así que no se pone el equipo en contención.", Files: []string{cmd}})
			gd.g.log("Orden cortada (sin culpable fuera de Microsoft): %s", cmd)
			go alertSessions("BlueShieldAA", "Se ha bloqueado una orden que borra las copias de seguridad de Windows:\n\n"+cmd+"\n\nSi no la has lanzado tú, abre BlueShieldAA → Anti-ransomware.")
		}
	}
}

func (gd *guardian) pathOf(pid int) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// findCulprits: los procesos que más han escrito en disco en los últimos segundos.
func (gd *guardian) findCulprits() []Culprit {
	procs := snapProcs(true)
	type cand struct {
		p     gProc
		delta uint64
	}
	var cs []cand
	for _, p := range procs {
		if p.PID <= 4 || p.PID == gd.self || p.Path == "" || isOurPath(p.Path, gd.cfg.InstallDir) {
			continue
		}
		prev, ok := gd.io[p.PID]
		d := p.Write
		if ok && p.Write >= prev {
			d = p.Write - prev
		}
		if d < 256<<10 {
			continue
		}
		meta := FileMeta(p.Path)
		if meta.Signed == "Microsoft" && !inList(p.Name, "contencion_bloquear") {
			continue
		}
		if meta.Signed == "Firmado" && TrustedVendor(meta.Company) {
			continue
		}
		cs = append(cs, cand{p, d})
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].delta > cs[j].delta })
	var out []Culprit
	for i, c := range cs {
		if i >= 3 {
			break
		}
		out = append(out, Culprit{PID: c.p.PID, Name: c.p.Name, Path: c.p.Path, Cmd: cmdLineOf(c.p.PID), Why: fmt.Sprintf("escribió %s en disco justo en el momento del ataque", human(int64(c.delta)))})
	}
	if len(out) > 0 {
		return out
	}
	// sin escrituras claras: programas sin firma arrancados hace poco desde carpetas de usuario
	for _, p := range procs {
		lp := strings.ToLower(p.Path)
		if p.Path == "" || time.Since(p.Start) > 15*time.Minute || !hasAny(lp, `\appdata\`, `\temp\`, `\downloads\`, `\users\public\`, `\programdata\`) {
			continue
		}
		if m := FileMeta(p.Path); m.Signed != "Microsoft" && m.Signed != "Firmado" {
			out = append(out, Culprit{PID: p.PID, Name: p.Name, Path: p.Path, Cmd: cmdLineOf(p.PID), Why: "programa sin firma arrancado hace poco desde una carpeta de usuario"})
		}
		if len(out) >= 3 {
			break
		}
	}
	return out
}

func human(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	}
	return fmt.Sprintf("%d KB", b>>10)
}

// respond: hay un ataque. En simulacro solo se avisa y se apunta lo que se haría.
func (gd *guardian) respond(reason string, ev []DecoyEvent, hint []Culprit) {
	t0 := time.Now()
	g := gd.g
	cul := append(hint, gd.findCulprits()...)
	cul = dedupeCulprits(cul)
	if gd.cfg.Mode != "contener" {
		gd.simulate("ataque", reason, ev, cul)
		return
	}
	// 1) congelar al culpable al instante
	for i := range cul {
		cul[i].Suspended = suspendPID(cul[i].PID)
	}
	inc := GuardIncident{ID: randID(), When: t0, Kind: "ataque", Reason: reason, Culprits: cul, Contained: true}
	for _, e := range ev {
		inc.Files = append(inc.Files, e.Path)
		if e.NewName != "" {
			inc.NewNames = append(inc.NewNames, e.NewName)
		}
	}
	c := gd.cont
	if !c.Active {
		c = Containment{Active: true, Since: t0, Reason: reason, Incident: inc.ID}
	}
	c.Culprits = dedupeCulprits(append(c.Culprits, cul...))
	gd.cont = c
	g.saveCont(c)
	// 2) solo Windows: primera pasada del bloqueo ya
	if gd.cfg.Lockdown {
		gd.lockdownPass(false)
	}
	// 3) aviso en pantalla (sin esperar)
	go alertSessions("BlueShieldAA · Posible ransomware", "Se ha detectado un posible ataque de ransomware y el equipo está en MODO CONTENCIÓN:\n\n"+
		"- Se ha detenido el programa sospechoso.\n- Solo pueden ejecutarse programas de Windows.\n- El equipo está desconectado de la red.\n\n"+
		"No apagues el equipo ni conectes discos o USB. Abre BlueShieldAA → Anti-ransomware para ver qué hacer.")
	// 4) cortar la red y parar los servicios que comparten el equipo
	if gd.cfg.Isolate {
		isolateNetwork(g, &gd.cont)
		inc.Isolated = gd.cont.Isolated
	}
	if gd.cfg.StopSvc {
		stopServices(g, &gd.cont)
	}
	// 5) detener del todo y guardar el ejecutable en cuarentena (queda para analizarlo)
	for i := range gd.cont.Culprits {
		x := &gd.cont.Culprits[i]
		if x.Quarantined || x.Path == "" {
			continue
		}
		_ = KillPID(x.PID)
		if FileMeta(x.Path).Signed == "Microsoft" {
			continue // powershell, cmd…: se detiene, pero no se toca el archivo de Windows
		}
		time.Sleep(300 * time.Millisecond)
		if msg := Quarantine(gd.st, x.Path, nil); msg == "" {
			x.Quarantined = true
			if l := QuarantineList(gd.st); len(l) > 0 {
				x.QID = l[0].ID
			}
		} else {
			gd.cont.Errors = append(gd.cont.Errors, x.Name+": "+msg)
		}
	}
	inc.Culprits = gd.cont.Culprits
	inc.Ms = int(time.Since(t0).Milliseconds())
	g.saveCont(gd.cont)
	g.addIncident(inc)
	g.log("ATAQUE: %s · culpables %d · aislado %v · servicios %d · %d ms", reason, len(cul), gd.cont.Isolated, len(gd.cont.Services), inc.Ms)
	writeEventLog("Posible ransomware: " + reason + ". El equipo está en modo contención.")
}

// simulate: modo simulacro y «Probar ahora». No se toca nada.
func (gd *guardian) simulate(kind, reason string, ev []DecoyEvent, cul []Culprit) {
	t0 := time.Now()
	inc := GuardIncident{ID: randID(), When: t0, Kind: kind, Reason: reason, Simulated: true, Culprits: cul}
	for _, e := range ev {
		inc.Files = append(inc.Files, e.Path)
		if e.NewName != "" {
			inc.NewNames = append(inc.NewNames, e.NewName)
		}
	}
	inc.WouldKill = gd.lockdownPass(true)
	svcs, _ := servicesToStop()
	for _, s := range svcs {
		inc.WouldStop = append(inc.WouldStop, s.Display)
	}
	inc.Ms = int(time.Since(t0).Milliseconds())
	gd.g.addIncident(inc)
	gd.g.log("SIMULACRO (%s): %s · cerraría %d programas y pararía %d servicios", kind, reason, len(inc.WouldKill), len(inc.WouldStop))
	title, msg := "BlueShieldAA · Prueba superada", "El guardián ha detectado el cambio en el documento trampa en "+fmt.Sprint(inc.Ms)+" ms.\n\nEs solo una prueba: no se ha detenido nada ni se ha cortado la red. En BlueShieldAA → Anti-ransomware verás lo que habría hecho."
	if kind != "prueba" {
		title, msg = "BlueShieldAA · Posible ransomware (simulacro)", "Se ha detectado un posible ataque de ransomware.\n\nLa protección está en MODO SIMULACRO: solo se avisa, no se ha detenido nada. Abre BlueShieldAA → Anti-ransomware para ver qué ha pasado."
	}
	go alertSessions(title, msg)
}

func dedupeCulprits(l []Culprit) []Culprit {
	seen := map[int]bool{}
	var out []Culprit
	for _, c := range l {
		if c.PID == 0 || seen[c.PID] {
			continue
		}
		seen[c.PID] = true
		out = append(out, c)
	}
	return out
}

// lockdownPass: cierra todo lo que no es Windows (o, en simulacro, devuelve lo que cerraría).
func (gd *guardian) lockdownPass(dry bool) []string {
	procs := snapProcs(true)
	byPID := map[int]gProc{}
	for _, p := range procs {
		byPID[p.PID] = p
	}
	install := gd.cfg.InstallDir
	if install == "" {
		install = filepath.Dir(selfExe())
	}
	cfg := gd.cfg
	cfg.InstallDir = install
	// procesos «nuestros»: BlueShieldAA, desbloquear.cmd y lo que lancen
	for pid, st := range gd.ours {
		if p, ok := byPID[pid]; !ok || !p.Start.Equal(st) {
			delete(gd.ours, pid)
		}
	}
	isOurs := func(p gProc) bool {
		if isOurPath(p.Path, install) {
			return true
		}
		if strings.EqualFold(p.Name, "cmd.exe") && strings.Contains(strings.ToLower(cmdLineOf(p.PID)), strings.ToLower(install)+`\desbloquear.cmd`) {
			return true
		}
		return false
	}
	for range 3 { // hijos y nietos
		for _, p := range procs {
			if _, ok := gd.ours[p.PID]; ok {
				continue
			}
			if isOurs(p) {
				gd.ours[p.PID] = p.Start
				continue
			}
			if st, ok := gd.ours[p.PPID]; ok && !p.Start.Before(st) {
				gd.ours[p.PID] = p.Start
			}
		}
	}
	var out []string
	for _, p := range procs {
		if p.PID <= 4 || p.PID == gd.self {
			continue
		}
		key := fmt.Sprintf("%d|%d", p.PID, p.Start.UnixNano())
		why, ok := gd.lock[key]
		if !ok {
			_, us := gd.ours[p.PID]
			meta := FileMeta(p.Path)
			why = lockdownWhy(p.Name, p.Path, meta.Signed, meta.Company, &cfg, us)
			if !dry {
				gd.lock[key] = why
			}
		}
		if why == "" {
			continue
		}
		label := p.Name + " — " + why
		if dry {
			out = append(out, label)
			continue
		}
		if KillPID(p.PID) == nil {
			gd.cont.Killed = appendCap(gd.cont.Killed, time.Now().Format("15:04:05")+"  "+label+"  ("+p.Path+")", 300)
			out = append(out, label)
		}
	}
	if !dry && len(out) > 0 {
		gd.g.saveCont(gd.cont)
	}
	if len(gd.lock) > 5000 {
		gd.lock = map[string]string{}
	}
	return out
}

func appendCap(l []string, s string, n int) []string {
	l = append(l, s)
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return l
}

// reapply: tras reiniciar en contención se vuelve a cortar la red y a parar servicios.
func (gd *guardian) reapply() {
	if gd.cont.Isolated || gd.cfg.Isolate {
		isolateNetwork(gd.g, &gd.cont)
	}
	if gd.cfg.StopSvc {
		stopServices(gd.g, &gd.cont)
	}
	gd.g.saveCont(gd.cont)
	go alertSessions("BlueShieldAA · Equipo en contención", "Este equipo sigue en MODO CONTENCIÓN por un posible ransomware.\n\nSolo pueden ejecutarse programas de Windows y no hay red. Abre BlueShieldAA → Anti-ransomware para ver cómo liberarlo.")
}

func (gd *guardian) orders() {
	dir := gd.g.p("ordenes")
	es, err := os.ReadDir(dir)
	if err != nil || len(es) == 0 {
		return
	}
	for _, e := range es {
		p := filepath.Join(dir, e.Name())
		var o GuardOrder
		err := readJSON(p, &o)
		_ = os.Remove(p)
		if err != nil || time.Since(o.When) > 10*time.Minute {
			continue
		}
		switch o.Cmd {
		case "prueba":
			if len(gd.rt.Decoys) == 0 {
				continue
			}
			d := gd.rt.Decoys[0]
			// se busca un señuelo .txt para no estropear un documento
			for _, x := range gd.rt.Decoys {
				if strings.HasSuffix(strings.ToLower(x.Path), ".txt") {
					d = x
					break
				}
			}
			gd.testPath = d.Path
			if f, err := os.OpenFile(d.Path, os.O_APPEND|os.O_WRONLY, 0); err == nil {
				f.Write([]byte("\r\n"))
				f.Close()
			}
		case "liberar":
			releaseContainment(gd.g, o.By)
			gd.cont = gd.g.cont()
			gd.lock = map[string]string{}
			seedDecoys(gd.cfg, &gd.rt)
		case "resolver":
			gd.g.updateIncident(o.Arg, func(i *GuardIncident) { i.Resolved = true })
		case "resembrar":
			gd.cfg = gd.g.cfg()
			seedDecoys(gd.cfg, &gd.rt)
		}
		gd.g.saveRt(gd.rt)
	}
}

// ---------- registro de Windows (Visor de eventos → Aplicación) ----------

func writeEventLog(msg string) {
	src, _ := windows.UTF16PtrFromString(AppName)
	h, err := windows.RegisterEventSource(nil, src)
	if err != nil {
		return
	}
	defer windows.DeregisterEventSource(h)
	m, _ := windows.UTF16PtrFromString(msg)
	_ = windows.ReportEvent(h, windows.EVENTLOG_ERROR_TYPE, 0, 4100, 0, 1, 0, &m, nil)
}

// ---------- tarea programada ----------

func guardTaskXML(exe string) []byte {
	x := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Guardián anti-ransomware de BlueShieldAA (solo actúa en este equipo)</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>4</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec><Command>"` + xmlEsc(exe) + `"</Command><Arguments>--guardian</Arguments></Exec></Actions>
</Task>`
	u := utf16.Encode([]rune(strings.ReplaceAll(x, "\n", "\r\n")))
	b := []byte{0xFF, 0xFE}
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return b
}

func xmlEsc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func schtasks(args ...string) (string, int, error) {
	return runExe(30*time.Second, filepath.Join(sysDir(), "schtasks.exe"), args...)
}

func installGuardTask() error {
	exe := selfExe()
	tmp := filepath.Join(os.TempDir(), "bsaa-guardian.xml")
	if err := os.WriteFile(tmp, guardTaskXML(exe), 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	out, code, err := schtasks("/Create", "/TN", guardTask, "/XML", tmp, "/F")
	if err != nil || code != 0 {
		return fmt.Errorf("no se pudo crear la tarea del guardián: %s", strings.TrimSpace(out))
	}
	_, _, _ = schtasks("/Run", "/TN", guardTask)
	return nil
}

func removeGuardTask() {
	_, _, _ = schtasks("/End", "/TN", guardTask)
	_, _, _ = schtasks("/Delete", "/TN", guardTask, "/F")
}

// ---------- inicio automático nuevo desde el ataque (para liberar) ----------

func newPersistence(since time.Time) []string {
	since = since.Add(-15 * time.Minute)
	var out []string
	runKeys := []string{`Software\Microsoft\Windows\CurrentVersion\Run`, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`}
	check := func(root registry.Key, rootName, path string) {
		k, err := registry.OpenKey(root, path, registry.READ)
		if err != nil {
			return
		}
		defer k.Close()
		st, err := k.Stat()
		if err != nil || st.ModTime().Before(since) {
			return
		}
		names, _ := k.ReadValueNames(0)
		for _, n := range names {
			v, _, _ := k.GetStringValue(n)
			out = append(out, rootName+`\`+path+` → `+n+": "+v)
		}
	}
	for _, p := range runKeys {
		check(registry.LOCAL_MACHINE, "HKLM", p)
	}
	if k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS); err == nil {
		sids, _ := k.ReadSubKeyNames(0)
		k.Close()
		for _, s := range sids {
			if strings.HasSuffix(s, "_Classes") {
				continue
			}
			for _, p := range runKeys[:2] {
				check(registry.USERS, `HKU\`+s, s+`\`+p)
			}
		}
	}
	walk := func(dir, label string, depth int) {
		var f func(d string, n int)
		f = func(d string, n int) {
			es, err := os.ReadDir(d)
			if err != nil {
				return
			}
			for _, e := range es {
				p := filepath.Join(d, e.Name())
				if e.IsDir() {
					if n < depth {
						f(p, n+1)
					}
					continue
				}
				if fi, err := e.Info(); err == nil && fi.ModTime().After(since) && !strings.EqualFold(e.Name(), "desktop.ini") {
					out = append(out, label+": "+p)
				}
			}
		}
		f(dir, 0)
	}
	walk(filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks"), "Tarea programada", 4)
	walk(filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\StartUp`), "Inicio (todos)", 0)
	users := filepath.Join(os.Getenv("SystemDrive")+`\`, "Users")
	if es, err := os.ReadDir(users); err == nil {
		for _, e := range es {
			walk(filepath.Join(users, e.Name(), `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`), "Inicio ("+e.Name()+")", 0)
		}
	}
	// servicios creados desde el ataque
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS); err == nil {
		names, _ := k.ReadSubKeyNames(0)
		k.Close()
		for _, n := range names {
			sk, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+n, registry.READ)
			if err != nil {
				continue
			}
			st, err := sk.Stat()
			img, _, _ := sk.GetStringValue("ImagePath")
			typ, _, _ := sk.GetIntegerValue("Type")
			sk.Close()
			// Solo servicios de Windows (no controladores) con la clave recién creada y nada de Microsoft
			if err != nil || st.ModTime().Before(since) || img == "" || typ&0x30 == 0 {
				continue
			}
			if m := FileMeta(ServiceExe(img, os.Getenv("SystemRoot"))); m.Signed != "Microsoft" {
				out = append(out, "Servicio "+n+": "+img)
			}
		}
	}
	return out
}

// runningCulprits: culpables que siguen vivos (mismo PID y misma ruta).
func runningCulprits(c Containment) []string {
	var out []string
	for _, x := range c.Culprits {
		if x.PID == 0 {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(x.PID))
		if err != nil {
			continue
		}
		var code uint32
		alive := windows.GetExitCodeProcess(h, &code) == nil && code == 259 // STILL_ACTIVE
		buf := make([]uint16, 1024)
		n := uint32(len(buf))
		same := windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil && strings.EqualFold(windows.UTF16ToString(buf[:n]), x.Path)
		windows.CloseHandle(h)
		if alive && same {
			out = append(out, fmt.Sprintf("%s (PID %d)", x.Name, x.PID))
		}
	}
	return out
}

// ---------- análisis completo con Microsoft Defender ----------

var scanMu sync.Mutex

func startDefenderScan(g guardFiles) string {
	scanMu.Lock()
	defer scanMu.Unlock()
	if s := g.scan(); s.Running && time.Since(s.Start) < 8*time.Hour {
		return "Ya hay un análisis en marcha."
	}
	exe := filepath.Join(os.Getenv("ProgramFiles"), "Windows Defender", "MpCmdRun.exe")
	if _, err := os.Stat(exe); err != nil {
		return "No se encuentra Microsoft Defender en este equipo. Analízalo con tu antivirus y marca la casilla «Analizado con otro antivirus»."
	}
	st := ScanState{Running: true, Start: time.Now()}
	_ = writeJSON(g.p("guardian-analisis.json"), st)
	go func() {
		out, code, err := runExe(8*time.Hour, exe, "-Scan", "-ScanType", "2")
		st.Running, st.End, st.Code = false, time.Now(), code
		lines := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
		for _, l := range lines {
			if l = strings.TrimSpace(l); l != "" {
				st.Tail = appendCap(st.Tail, l, 12)
			}
		}
		switch {
		case err != nil && code == 0:
			st.Error = "El análisis no ha podido terminar: " + err.Error()
		case code == 0:
			st.OK = true
		case code == 2:
			st.OK = false
		default:
			st.Error = fmt.Sprintf("Microsoft Defender devolvió el código %d (¿está desactivado porque hay otro antivirus?).", code)
		}
		_ = writeJSON(g.p("guardian-analisis.json"), st)
		g.log("Análisis completo de Defender: código %d, sin amenazas %v", code, st.OK)
	}()
	return ""
}

// ---------- estado para la ventana ----------

func guardStatus(g guardFiles, portable bool) map[string]any {
	cfg := g.cfg()
	rt := g.rt()
	c := g.cont()
	inc := g.incidents()
	if inc == nil {
		inc = []GuardIncident{}
	}
	folders := rt.Folders
	if folders == nil {
		folders = []GuardFolder{}
	}
	task := !portable && guardTaskExists()
	out := map[string]any{
		"portable": portable, "enabled": cfg.Enabled, "mode": cfg.Mode, "isolate": cfg.Isolate, "stopSvc": cfg.StopSvc, "lockdown": cfg.Lockdown,
		"running": !rt.Beat.IsZero() && time.Since(rt.Beat) < guardStaleAt, "beat": rt.Beat, "guardVersion": rt.Version, "task": task,
		"decoys": len(rt.Decoys), "folders": folders, "custom": nzs(cfg.Custom), "errors": nzs(rt.Errors),
		"incidents": inc, "containment": c, "scan": g.scan(),
	}
	return out
}

// guardTaskExists mira el archivo de la tarea (sin lanzar schtasks cada vez).
func guardTaskExists() bool {
	_, err := os.Stat(filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks", "BlueShieldAA", "Guardian"))
	return err == nil
}

func resetTaskCache() {}

func nzs(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

func guardChecks(g guardFiles, reviewed, externalAV bool) map[string]any {
	c := g.cont()
	if !c.Active {
		return map[string]any{"active": false}
	}
	newAttacks := 0
	for _, i := range g.incidents() {
		if i.Kind == "ataque" && i.When.After(c.Since.Add(30*time.Second)) {
			newAttacks++
		}
	}
	persist := newPersistence(c.Since)
	checks := ReleaseChecks(c, g.scan(), runningCulprits(c), persist, newAttacks, reviewed, externalAV)
	return map[string]any{"active": true, "checks": checks, "can": CanRelease(checks)}
}

// guardJSON es solo para depurar desde la consola.
func guardJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
