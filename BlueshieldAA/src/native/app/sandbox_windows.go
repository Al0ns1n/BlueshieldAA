//go:build windows

package main

// Análisis dinámico con Windows Sandbox (Windows 10/11 Pro, Enterprise o Education).
// El archivo se abre en una máquina desechable SIN RED; nada de lo que haga llega a este
// equipo, y Windows la borra entera al cerrarse. Solo actúa en este equipo.

import (
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type SBStatus struct {
	Available bool   `json:"available"`
	Enabled   bool   `json:"enabled"`
	CanEnable bool   `json:"canEnable"`
	Reason    string `json:"reason"`
	Busy      bool   `json:"busy"`
}

type sbJob struct {
	ID      string
	Dir     string
	Path    string
	Secs    int
	State   string
	Err     string
	Started time.Time
	Result  *SBResult
	Final   *FAResult
	cmd     *exec.Cmd
	stop    bool
}

var sbMu sync.Mutex
var sbJobs = map[string]*sbJob{}
var sbCurrent string

func sandboxExe() string { return filepath.Join(sysDir(), "WindowsSandbox.exe") }

func SandboxStatus() SBStatus {
	sbMu.Lock()
	busy := sbCurrent != ""
	sbMu.Unlock()
	type raw struct {
		State   string `json:"state"`
		Edition string `json:"edition"`
		Virt    bool   `json:"virt"`
		Hyper   bool   `json:"hyper"`
	}
	r, err := psObj[raw](`$o=@{}; $f=Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM; if($f){$o.state=[string]$f.State}
$o.edition=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
$c=Get-CimInstance Win32_Processor | Select-Object -First 1; $o.virt=[bool]$c.VirtualizationFirmwareEnabled
$o.hyper=[bool](Get-CimInstance Win32_ComputerSystem).HypervisorPresent
$o | ConvertTo-Json -Compress`, time.Minute)
	st := SBStatus{Busy: busy}
	if err != nil {
		st.Reason = "No se ha podido comprobar si Windows Sandbox está disponible: " + err.Error()
		return st
	}
	_, exeErr := os.Stat(sandboxExe())
	switch {
	case strings.Contains(strings.ToLower(r.Edition), "core") || r.State == "":
		st.Reason = "Windows Sandbox no está disponible en Windows " + ternary(strings.Contains(strings.ToLower(r.Edition), "core"), "Home", r.Edition) + ". Hace falta Windows 10/11 Pro, Enterprise o Education."
	case !r.Virt && !r.Hyper:
		st.Available = true
		st.Reason = "La virtualización está desactivada en la BIOS/UEFI del equipo. Actívala (Intel VT-x / AMD-V) para poder usar el entorno aislado."
	case r.State == "Enabled" && exeErr == nil:
		st.Available, st.Enabled = true, true
	case r.State == "Enabled":
		st.Available = true
		st.Reason = "Windows Sandbox está activado pero falta reiniciar el equipo para poder usarlo."
	default:
		st.Available, st.CanEnable = true, true
		st.Reason = "Windows Sandbox está disponible pero no activado. Se activa una vez y hay que reiniciar."
	}
	return st
}

func SandboxEnable(e *Engine) string {
	e.Log("cmd", "> Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart")
	out, err := runPS(`$r=Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart -ErrorAction Stop; if($r.RestartNeeded){'REINICIAR'}else{'OK'}`, 10*time.Minute)
	if err != nil {
		return "No se ha podido activar: " + err.Error()
	}
	if strings.Contains(out, "REINICIAR") {
		e.Log("ok", "✔ Windows Sandbox activado. Falta reiniciar el equipo.")
		return "Activado. Reinicia el equipo para poder usar el entorno aislado."
	}
	return ""
}

// SandboxRun prepara y arranca el entorno aislado. Devuelve el id del trabajo o "ERROR:motivo".
func SandboxRun(a *App, path string, secs int) string {
	if secs < 30 || secs > 300 {
		secs = 60
	}
	sbMu.Lock()
	if sbCurrent != "" {
		sbMu.Unlock()
		return "ERROR:Ya hay un análisis en el entorno aislado en marcha."
	}
	id := randID()
	sbCurrent = id
	sbMu.Unlock()
	fail := func(msg string) string {
		sbMu.Lock()
		sbCurrent = ""
		sbMu.Unlock()
		return "ERROR:" + msg
	}
	exe, _ := os.Executable()
	monitor := filepath.Join(filepath.Dir(exe), "sandbox-monitor.ps1")
	if _, err := os.Stat(monitor); err != nil {
		return fail("Falta sandbox-monitor.ps1 junto al programa. Reinstala BlueShieldAA.")
	}
	if _, err := os.Stat(sandboxExe()); err != nil {
		return fail("Windows Sandbox no está activado en este equipo.")
	}
	cleanOldJobs(a.St)
	dir := a.St.Path("sandbox", id)
	in, out := filepath.Join(dir, "in"), filepath.Join(dir, "out")
	if err := os.MkdirAll(in, 0o755); err != nil {
		return fail(err.Error())
	}
	_ = os.MkdirAll(out, 0o755)
	if err := copyFile(path, filepath.Join(in, "muestra.bin")); err != nil {
		return fail("No se puede leer el archivo: " + err.Error())
	}
	if err := copyFile(monitor, filepath.Join(in, "sandbox-monitor.ps1")); err != nil {
		return fail(err.Error())
	}
	name := filepath.Base(path)
	_ = writeJSON(filepath.Join(in, "config.json"), map[string]any{"name": name, "seconds": secs})
	wsb := `<Configuration>
  <Networking>Disable</Networking>
  <vGPU>Disable</vGPU>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <ProtectedClient>Enable</ProtectedClient>
  <MemoryInMB>4096</MemoryInMB>
  <MappedFolders>
    <MappedFolder><HostFolder>` + html.EscapeString(in) + `</HostFolder><SandboxFolder>C:\bs\in</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>` + html.EscapeString(out) + `</HostFolder><SandboxFolder>C:\bs\out</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>cmd.exe /c copy /y C:\bs\in\sandbox-monitor.ps1 C:\Users\WDAGUtilityAccount\bs-monitor.ps1 &amp;&amp; powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File C:\Users\WDAGUtilityAccount\bs-monitor.ps1</Command>
  </LogonCommand>
</Configuration>`
	wsbPath := filepath.Join(dir, "analisis.wsb")
	if err := os.WriteFile(wsbPath, []byte(wsb), 0o644); err != nil {
		return fail(err.Error())
	}
	job := &sbJob{ID: id, Dir: dir, Path: path, Secs: secs, State: "arrancando", Started: time.Now()}
	job.cmd = hidden(exec.Command(sandboxExe(), wsbPath))
	if err := job.cmd.Start(); err != nil {
		return fail("No se pudo abrir Windows Sandbox: " + err.Error())
	}
	sbMu.Lock()
	sbJobs[id] = job
	sbMu.Unlock()
	a.E.Log("title", "━━ Entorno aislado: %s (%d s, sin red) ━━", name, secs)
	go a.watchSandbox(job)
	return id
}

func (a *App) watchSandbox(j *sbJob) {
	defer func() {
		sbMu.Lock()
		if sbCurrent == j.ID {
			sbCurrent = ""
		}
		sbMu.Unlock()
		_ = os.Remove(filepath.Join(j.Dir, "in", "muestra.bin"))
	}()
	out := filepath.Join(j.Dir, "out")
	deadline := time.Now().Add(time.Duration(j.Secs+240) * time.Second)
	lastStep := ""
	for {
		time.Sleep(time.Second)
		sbMu.Lock()
		stop := j.stop
		sbMu.Unlock()
		if b, err := os.ReadFile(filepath.Join(out, "progreso.txt")); err == nil {
			lines := strings.Split(strings.TrimSpace(strings.TrimPrefix(string(b), "\ufeff")), "\n")
			step := strings.TrimSpace(lines[len(lines)-1])
			if step != lastStep {
				lastStep = step
				a.E.Log("out", "entorno aislado: %s", step)
			}
			sbMu.Lock()
			switch {
			case strings.HasPrefix(step, "observando"), step == "abriendo":
				j.State = "observando"
			case step == "recogiendo", step == "fin":
				j.State = "recogiendo"
			case step == "arrancado":
				j.State = "preparando"
			}
			sbMu.Unlock()
		}
		if b, err := os.ReadFile(filepath.Join(out, "informe.json")); err == nil {
			rep, perr := ParseSBReport(b)
			sbMu.Lock()
			if perr != nil {
				j.State, j.Err = "error", "El informe del entorno aislado no se ha podido leer."
			} else {
				kind := ""
				if a.lastFA != nil && strings.EqualFold(a.lastFA.Path, j.Path) {
					kind = a.lastFA.Kind
				}
				res := BuildDynamic(rep, kind)
				j.Result = &res
				if a.lastFA != nil && strings.EqualFold(a.lastFA.Path, j.Path) {
					cp := *a.lastFA
					cp.Findings = append([]Finding{}, a.lastFA.Findings...)
					CombineVerdict(&cp, res)
					j.Final = &cp
				}
				j.State = "terminado"
				a.E.Log(ternary(res.Verdict == "Limpio", "ok", "warn"), "Entorno aislado: %s · %s", res.Verdict, res.Summary)
			}
			sbMu.Unlock()
			a.waitSandboxClosed(j, 20*time.Second)
			return
		}
		if stop || time.Now().After(deadline) {
			sbMu.Lock()
			j.State = "error"
			j.Err = ternary(stop, "Cancelado.", "El entorno aislado no ha respondido a tiempo (Windows Sandbox puede tardar en arrancar la primera vez). Vuelve a intentarlo.")
			sbMu.Unlock()
			a.closeSandbox()
			return
		}
	}
}

func (a *App) waitSandboxClosed(j *sbJob, d time.Duration) {
	done := make(chan struct{})
	go func() { _ = j.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		a.closeSandbox()
	}
}

// closeSandbox cierra Windows Sandbox (todo lo que hubiera dentro desaparece).
func (a *App) closeSandbox() {
	_, _ = runPS(`Get-Process WindowsSandbox, WindowsSandboxClient, WindowsSandboxRemoteSession, WindowsSandboxServer -ErrorAction SilentlyContinue | Stop-Process -Force`, 30*time.Second)
}

type SBPoll struct {
	State  string    `json:"state"`
	Err    string    `json:"err,omitempty"`
	Secs   int       `json:"secs"`
	Total  int       `json:"total"`
	Shots  []string  `json:"shots"`
	Result *SBResult `json:"result,omitempty"`
	Final  *FAResult `json:"final,omitempty"`
}

func SandboxPoll(id string) SBPoll {
	sbMu.Lock()
	j := sbJobs[id]
	sbMu.Unlock()
	if j == nil {
		return SBPoll{State: "error", Err: "Ese análisis ya no existe."}
	}
	shots, _ := filepath.Glob(filepath.Join(j.Dir, "out", "captura_*.jpg"))
	sort.Strings(shots)
	names := []string{}
	for _, s := range shots {
		names = append(names, filepath.Base(s))
	}
	sbMu.Lock()
	defer sbMu.Unlock()
	return SBPoll{State: j.State, Err: j.Err, Secs: int(time.Since(j.Started).Seconds()), Total: j.Secs, Shots: names, Result: j.Result, Final: j.Final}
}

// SandboxShot devuelve una captura como data URI (solo nombres captura_NN.jpg del trabajo).
func SandboxShot(id, name string) string {
	sbMu.Lock()
	j := sbJobs[id]
	sbMu.Unlock()
	if j == nil || filepath.Base(name) != name || !strings.HasPrefix(name, "captura_") || !strings.HasSuffix(name, ".jpg") {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(j.Dir, "out", name))
	if err != nil {
		return ""
	}
	return "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(b)
}

func SandboxStop(id string) {
	sbMu.Lock()
	if j := sbJobs[id]; j != nil {
		j.stop = true
	}
	sbMu.Unlock()
}

// cleanOldJobs deja solo los 5 últimos análisis (capturas incluidas).
func cleanOldJobs(st *Store) {
	dirs, _ := filepath.Glob(st.Path("sandbox", "*"))
	if len(dirs) <= 5 {
		return
	}
	type d struct {
		p string
		t time.Time
	}
	var l []d
	for _, p := range dirs {
		if fi, err := os.Stat(p); err == nil {
			l = append(l, d{p, fi.ModTime()})
		}
	}
	sort.Slice(l, func(a, b int) bool { return l[a].t.After(l[b].t) })
	for _, x := range l[5:] {
		_ = os.RemoveAll(x.p)
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	o, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(o, in); err != nil {
		o.Close()
		return err
	}
	return o.Close()
}

var _ = fmt.Sprint
