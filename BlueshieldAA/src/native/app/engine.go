package main

// Motor de BlueShieldAA 4.x: una lista única de elementos (programas, ajustes, puertos…)
// que rellenan los "analizadores" y que se corrigen con "acciones". La interfaz consulta
// el estado cada poco (caState) y solo recibe la lista cuando ha cambiado.

import (
	"fmt"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
)

type Item struct {
	ID        string   `json:"id"`
	Category  string   `json:"category"`
	Name      string   `json:"name"`
	Detail    string   `json:"detail"`
	Current   string   `json:"current"`
	Available string   `json:"available"`
	Status    string   `json:"status"`
	Action    string   `json:"action"`
	Arg       string   `json:"arg,omitempty"` // dato para la acción (id de winget, ruta, puerto…)
	Checked   bool     `json:"checked"`
	Tag       string   `json:"tag,omitempty"`
	Group     string   `json:"group,omitempty"`
	Icon      string   `json:"icon,omitempty"`
	Priority  string   `json:"priority,omitempty"`
	Exploited bool     `json:"exploited,omitempty"`
	EPSS      float64  `json:"epss,omitempty"`
	Confirmed bool     `json:"confirmed,omitempty"`
	Alt       string   `json:"alt,omitempty"`
	AltLabel  string   `json:"altLabel,omitempty"`
	Vulns     []string `json:"vulns,omitempty"`
	CVEs      []string `json:"cves,omitempty"`
	Bytes     int64    `json:"bytes,omitempty"`
	Reboot    bool     `json:"-"`
}

// Estados que cuentan como pendientes (igual que PENDING en la interfaz).
var pendingStatus = map[string]bool{"Vulnerable": true, "Actualizar": true, "Revisar": true, "Falló": true, "Error": true, "Pendiente": true, "Abierto": true}

// Apartado de cada categoría (igual que PAGE_CATS en la interfaz).
var pageCats = map[string][]string{
	"updates": {"Programas", "Windows", "Node.js", "npm global", "Python", "Proyecto", "Docker", "Vulnerabilidades"},
	"protect": {"Seguridad", "Navegadores", "Secretos", "Copias", "Endurecimiento", "Pentest"},
	"changes": {"Cambios"},
	"net":     {"Red", "Intrusiones", "Web", "Servidores", "Red local"},
	"hw":      {"Hardware"},
	"clean":   {"Limpieza"},
	"apps":    {"Aplicaciones"},
	"events":  {"Eventos"},
}

// Scanner: una comprobación que devuelve elementos de una o varias categorías.
type Scanner struct {
	Name  string   // texto corto para "Analizando …"
	Cats  []string // categorías que sustituye al terminar
	Slow  bool     // en el arranque rápido va en segundo plano
	Order int
	Cmd   string // orden que se enseña en la consola al empezar
	Run   func(e *Engine) ([]*Item, error)
}

// Action: corrige un elemento. Devuelve el nuevo estado (vacío = "Al día") o un error.
type Action func(e *Engine, it *Item) (string, error)

type LogLine struct {
	Seq int    `json:"-"`
	T   string `json:"t"`
	L   string `json:"l"`
	M   string `json:"m"`
}

type Engine struct {
	mu       sync.Mutex
	St       *Store
	items    []*Item
	ver      int
	busy     bool
	bgUpd    bool
	status   string
	prog     [2]int
	result   string
	lastScan time.Time
	logs     []LogLine
	logSeq   int
	scanners []Scanner
	actions  map[string]Action
	alts     map[string]Action

	// Para la ventana de progreso: fase, escena, qué corre, qué ha terminado y la subtarea
	phase   string
	act     string
	running []string
	done    []string
	queue   []string
	step    int
	steps   int
	item    string
	sub     string
	subPct  int
}

func NewEngine(st *Store) *Engine {
	e := &Engine{St: st, status: "Listo.", actions: map[string]Action{}, alts: map[string]Action{}}
	if sv, ok := st.LoadItems(); ok {
		e.items = sv.Items
		e.lastScan = sv.When
		e.applyPrefs()
	}
	return e
}

func (e *Engine) AddScanner(s Scanner)            { e.scanners = append(e.scanners, s) }
func (e *Engine) AddAction(name string, a Action) { e.actions[name] = a }
func (e *Engine) AddAlt(name string, a Action)    { e.alts[name] = a }

// ---------- registro ----------

func (e *Engine) Log(level, format string, a ...any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.logSeq++
	e.logs = append(e.logs, LogLine{Seq: e.logSeq, T: time.Now().Format("15:04:05"), L: level, M: fmt.Sprintf(format, a...)})
	if len(e.logs) > 2000 {
		e.logs = e.logs[len(e.logs)-2000:]
	}
}

func (e *Engine) setStatus(s string) { e.mu.Lock(); e.status = s; e.mu.Unlock() }

// ---------- estado para la interfaz ----------

type StateOut struct {
	Phase    string    `json:"phase"`
	Act      string    `json:"act"`
	Running  []string  `json:"running"`
	Done     []string  `json:"done"`
	Queue    []string  `json:"queue"`
	Step     int       `json:"step"`
	Steps    int       `json:"steps"`
	Item     string    `json:"item"`
	Sub      string    `json:"sub"`
	SubPct   int       `json:"subPct"`
	Ver      int       `json:"ver"`
	Items    []*Item   `json:"items"`
	Logs     []LogLine `json:"logs"`
	LogNext  int       `json:"logNext"`
	Busy     bool      `json:"busy"`
	BgUpd    bool      `json:"bgUpd"`
	Status   string    `json:"status"`
	Prog     [2]int    `json:"prog"`
	Result   string    `json:"result"`
	LastScan string    `json:"lastScan"`
}

func (e *Engine) State(ver, logNext int) StateOut {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := StateOut{Ver: e.ver, Busy: e.busy, BgUpd: e.bgUpd, Status: e.status, Prog: e.prog, Result: e.result, LogNext: e.logSeq,
		Phase: e.phase, Act: e.act, Running: append([]string{}, e.running...), Done: append([]string{}, e.done...), Queue: append([]string{}, e.queue...),
		Step: e.step, Steps: e.steps, Item: e.item, Sub: e.sub, SubPct: e.subPct}
	if !e.lastScan.IsZero() {
		out.LastScan = e.lastScan.Format(time.RFC3339)
	}
	if ver != e.ver {
		out.Items = copyItems(e.items)
		if out.Items == nil {
			out.Items = []*Item{}
		}
	}
	for _, l := range e.logs {
		if l.Seq > logNext {
			out.Logs = append(out.Logs, l)
		}
	}
	return out
}

func (e *Engine) Busy() bool { e.mu.Lock(); defer e.mu.Unlock(); return e.busy }

// Items devuelve una copia: quien la lea (JSON, informes) no choca con el motor.
func (e *Engine) Items() []*Item {
	e.mu.Lock()
	defer e.mu.Unlock()
	return copyItems(e.items)
}

func copyItems(l []*Item) []*Item {
	out := make([]*Item, len(l))
	for i, it := range l {
		c := *it
		c.Vulns = append([]string(nil), it.Vulns...)
		c.CVEs = append([]string(nil), it.CVEs...)
		out[i] = &c
	}
	return out
}

func (e *Engine) find(id string) *Item {
	for _, it := range e.items {
		if it.ID == id {
			return it
		}
	}
	return nil
}

// applyPrefs marca lo ocultado/excluido y lo seleccionado. Llamar con e.mu tomado o antes de publicar.
func (e *Engine) applyPrefs() {
	e.St.cfgMu.Lock()
	defer e.St.cfgMu.Unlock()
	cfg := e.St.Cfg
	for _, it := range e.items {
		if pendingStatus[it.Status] && cfg.Dismissed[it.ID] {
			it.Status = "Oculto"
		}
		if (it.Action == "winget" || it.Action == "openapp") && it.Arg != "" && cfg.Excluded[it.Arg] && pendingStatus[it.Status] {
			it.Status = "Oculto"
			it.Alt, it.AltLabel = "allowupdate", "Volver a permitir"
		}
		if c, ok := cfg.Checked[it.ID]; ok {
			it.Checked = c && canAct(it)
		} else {
			it.Checked = false
		}
	}
}

func canAct(it *Item) bool {
	if it.Action == "" || it.Action == "none" {
		return false
	}
	switch it.Status {
	case "Actualizado", "Abierto", "Pendiente", "Limpio", "Desinstalada", "Oculto":
		return false
	}
	return true
}

// Score: misma fórmula que la interfaz (healthOf).
func Score(items []*Item) int {
	v, u, x := 0, 0, 0
	for _, i := range items {
		switch i.Status {
		case "Vulnerable":
			v++
		case "Actualizar", "Revisar":
			u++
		}
		if i.Exploited && i.Status != "Actualizado" && i.Status != "Al día" && i.Status != "Oculto" {
			x++
		}
	}
	s := 100 - 12*v - 3*u - 10*x
	if s < 0 {
		s = 0
	}
	return s
}

// replaceCats sustituye los elementos de unas categorías por los nuevos, sin vaciar el resto.
func (e *Engine) replaceCats(cats []string, fresh []*Item) {
	e.mu.Lock()
	defer e.mu.Unlock()
	drop := map[string]bool{}
	for _, c := range cats {
		drop[c] = true
	}
	for _, it := range fresh {
		drop[it.Category] = true
	}
	keep := e.items[:0:0]
	for _, it := range e.items {
		if !drop[it.Category] {
			keep = append(keep, it)
		}
	}
	seen := map[string]bool{}
	for _, it := range keep {
		seen[it.ID] = true
	}
	for _, it := range fresh {
		if it.ID == "" {
			it.ID = it.Category + ":" + it.Name
		}
		if seen[it.ID] {
			continue
		}
		seen[it.ID] = true
		if it.Current == "" {
			it.Current = "-"
		}
		if it.Available == "" {
			it.Available = "-"
		}
		if it.Action == "" {
			it.Action = "none"
		}
		keep = append(keep, it)
	}
	sortItems(keep)
	e.items = keep
	e.applyPrefs()
	e.ver++
}

var statusRank = map[string]int{"Vulnerable": 0, "Falló": 1, "Error": 1, "Actualizar": 2, "Revisar": 3, "Abierto": 4, "Pendiente": 5, "Info": 6, "Al día": 7, "Actualizado": 7, "Limpio": 8, "Limpiable": 6, "Oculto": 9}

func sortItems(l []*Item) {
	sort.SliceStable(l, func(a, b int) bool {
		ra, rb := statusRank[l[a].Status], statusRank[l[b].Status]
		if l[a].Exploited != l[b].Exploited {
			return l[a].Exploited
		}
		if ra != rb {
			return ra < rb
		}
		return strings.ToLower(l[a].Name) < strings.ToLower(l[b].Name)
	})
}

// ---------- análisis ----------

// Scan analiza todo. quick=true (arranque): lo lento va en segundo plano y la ventana queda libre.
func (e *Engine) Scan(quick bool) {
	e.mu.Lock()
	if e.busy {
		e.mu.Unlock()
		return
	}
	e.busy, e.result = true, ""
	e.phase, e.act, e.done, e.running, e.item, e.sub, e.subPct, e.queue = "", "scan", nil, nil, "", "", -1, nil
	e.mu.Unlock()
	e.Log("title", "━━ Análisis del equipo · BlueShieldAA %s ━━", AppVersion)

	var fg, bg []Scanner
	for _, s := range e.scanners {
		if quick && s.Slow {
			bg = append(bg, s)
		} else {
			fg = append(fg, s)
		}
	}
	e.runScanners(fg, true)
	items := e.Items()
	sc := Score(items)
	e.mu.Lock()
	e.lastScan = time.Now()
	e.result = fmt.Sprintf("Análisis terminado: puntuación %d de 100, %d aviso(s) pendientes.", sc, countPending(items))
	e.busy, e.status, e.prog = false, "Listo.", [2]int{0, 0}
	e.resetProgress()
	e.mu.Unlock()
	e.Log("ok", "✔ %s", e.result)
	if len(bg) == 0 {
		e.St.AddScore(sc)
		e.St.SaveItems(items)
		return
	}
	go func() {
		e.mu.Lock()
		e.bgUpd = true
		e.mu.Unlock()
		e.runScanners(bg, false)
		e.mu.Lock()
		e.bgUpd = false
		e.mu.Unlock()
		items := e.Items()
		e.St.AddScore(Score(items))
		e.St.SaveItems(items)
	}()
}

func countPending(items []*Item) int {
	n := 0
	for _, i := range items {
		if pendingStatus[i.Status] {
			n++
		}
	}
	return n
}

func (e *Engine) runScanners(list []Scanner, progress bool) {
	sort.SliceStable(list, func(a, b int) bool { return list[a].Order < list[b].Order })
	var wg sync.WaitGroup
	var rmu sync.Mutex
	running := map[string]bool{}
	done := 0
	upd := func() {
		if !progress {
			return
		}
		names := []string{}
		for n := range running {
			names = append(names, n)
		}
		sort.Strings(names)
		e.mu.Lock()
		e.prog = [2]int{done, len(list)}
		e.running, e.step, e.steps = names, done, len(list)
		if len(names) > 0 {
			e.status = "Analizando " + strings.Join(names, ", ") + "..."
		}
		e.mu.Unlock()
	}
	// como mucho 2 a la vez: cada analizador puede lanzar PowerShell, y varios juntos se notan
	sem := make(chan struct{}, 2)
	for _, s := range list {
		wg.Add(1)
		go func(s Scanner) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rmu.Lock()
			running[s.Name] = true
			upd()
			rmu.Unlock()
			t0 := time.Now()
			if s.Cmd != "" {
				e.Cmd("%s", s.Cmd)
			}
			items, err := safeRun(s, e)
			if err != nil {
				e.Log("err", "✖ %s: %v", s.Name, err)
			} else {
				e.replaceCats(s.Cats, items)
				e.Log("ok", "✔ %s: %d elemento(s) en %.1f s", s.Name, len(items), time.Since(t0).Seconds())
			}
			rmu.Lock()
			delete(running, s.Name)
			done++
			if progress {
				e.mu.Lock()
				e.done = append(e.done, s.Name)
				e.mu.Unlock()
			}
			upd()
			rmu.Unlock()
		}(s)
	}
	wg.Wait()
}

// panicHook anota en fallos.txt los fallos capturados (lo pone main en Windows).
var panicHook = func(where string, r any, stack []byte) {}

func safeRun(s Scanner, e *Engine) (items []*Item, err error) {
	defer func() {
		if r := recover(); r != nil {
			panicHook("analizador "+s.Name, r, debug.Stack())
			err = fmt.Errorf("fallo interno: %v", r)
		}
	}()
	return s.Run(e)
}

// ---------- selección y plan ----------

func (e *Engine) SetChecked(id string, v bool) {
	e.mu.Lock()
	if it := e.find(id); it != nil {
		it.Checked = v && canAct(it)
	}
	e.St.WithCfg(func(c *Config) { c.Checked[id] = v })
	e.mu.Unlock()
	e.St.SaveConfig()
}

func (e *Engine) Recommend(page string) {
	e.mu.Lock()
	cats := map[string]bool{}
	for p, cs := range pageCats {
		if page == "all" || page == "home" || p == page {
			for _, c := range cs {
				cats[c] = true
			}
		}
	}
	for _, it := range e.items {
		if !cats[it.Category] {
			continue
		}
		rec := canAct(it) && (it.Status == "Vulnerable" || it.Status == "Actualizar" || (it.Status == "Revisar" && safeFix[it.Action]))
		if rec {
			it.Checked = true
			id := it.ID
			e.St.WithCfg(func(c *Config) { c.Checked[id] = true })
		}
	}
	e.ver++
	e.mu.Unlock()
	e.St.SaveConfig()
}

// Acciones que se pueden marcar solas al pulsar "Marcar recomendados".
var safeFix = map[string]bool{"firewall": true, "defsig": true, "smb1": true, "guestoff": true, "rdpnla": true, "auditlogon": true, "winget": true, "clean": true, "restorepoint": true}

func (e *Engine) Uncheck() {
	e.mu.Lock()
	for _, it := range e.items {
		it.Checked = false
	}
	e.St.WithCfg(func(c *Config) { c.Checked = map[string]bool{} })
	e.ver++
	e.mu.Unlock()
	e.St.SaveConfig()
}

type Plan struct {
	Count    int      `json:"count"`
	Names    []string `json:"names"`
	Warnings []string `json:"warnings"`
}

func (e *Engine) Plan(ids []string) Plan {
	e.mu.Lock()
	defer e.mu.Unlock()
	p := Plan{Names: []string{}, Warnings: []string{}}
	w := map[string]bool{}
	for _, id := range ids {
		it := e.find(id)
		if it == nil || !canAct(it) {
			continue
		}
		p.Count++
		if len(p.Names) < 15 {
			p.Names = append(p.Names, it.Name)
		}
		switch it.Action {
		case "winget":
			w["Los programas que se actualicen se cerrarán un momento si están abiertos. Guarda tu trabajo antes."] = true
		case "rdpoff":
			w["Se desactivará el Escritorio remoto: nadie podrá conectarse a este equipo en remoto."] = true
		case "smb1":
			w["Desactivar SMBv1 puede requerir reiniciar. Algún aparato muy antiguo (NAS, impresoras) podría dejar de compartir carpetas."] = true
		case "clean":
			w["Los archivos temporales borrados no se pueden recuperar."] = true
		case "uninstall":
			w["Las aplicaciones desinstaladas se pueden volver a instalar desde Microsoft Store."] = true
		}
		if it.Reboot {
			w["Algún cambio necesita reiniciar el equipo para aplicarse."] = true
		}
	}
	for k := range w {
		p.Warnings = append(p.Warnings, k)
	}
	sort.Strings(p.Warnings)
	return p
}

// Run ejecuta las acciones de los elementos indicados, uno detrás de otro.
func (e *Engine) Run(ids []string) {
	e.mu.Lock()
	if e.busy {
		e.mu.Unlock()
		return
	}
	e.busy, e.result = true, ""
	var todo []*Item
	for _, id := range ids {
		if it := e.find(id); it != nil && canAct(it) {
			todo = append(todo, it)
		}
	}
	e.phase = runPhase(todo)
	e.queue = nil
	for _, it := range todo {
		e.queue = append(e.queue, it.Name)
	}
	e.act, e.done, e.running, e.steps, e.step, e.sub, e.subPct = actScene(""), nil, nil, len(todo), 0, "", -1
	e.mu.Unlock()
	e.Log("title", "━━ %s: %d elemento(s) ━━", map[string]string{"update": "Aplicando cambios", "clean": "Liberando espacio", "fix": "Aplicando ajustes de seguridad"}[e.phase], len(todo))

	restore := false
	e.St.WithCfg(func(c *Config) { restore = c.Settings.Restore })
	if restore && needsRestorePoint(todo) {
		if a, ok := e.actions["restorepoint"]; ok {
			e.mu.Lock()
			e.act, e.item = "restore", "Punto de restauración"
			e.mu.Unlock()
			e.setStatus("Creando un punto de restauración…")
			if _, err := a(e, &Item{Name: "Punto de restauración"}); err != nil {
				e.Log("warn", "No se pudo crear el punto de restauración: %v", err)
			} else {
				e.Log("ok", "Punto de restauración creado antes de los cambios.")
			}
		}
	}

	ok, fail := 0, 0
	for i, it := range todo {
		e.mu.Lock()
		e.prog = [2]int{i * 100, len(todo) * 100}
		e.status = "Procesando " + it.Name + "..."
		e.step, e.item, e.act, e.sub, e.subPct = i, it.Name, actScene(it.Action), "", -1
		e.mu.Unlock()
		e.Log("title", "▸ [%d/%d] %s", i+1, len(todo), it.Name)
		a, found := e.actions[it.Action]
		var st string
		var err error
		if !found {
			err = fmt.Errorf("esta acción todavía no está disponible en la versión %s", AppVersion)
		} else {
			st, err = runAction(a, e, it)
		}
		e.mu.Lock()
		if err != nil {
			fail++
			it.Status = "Falló"
			it.Detail = strings.TrimSpace(it.Detail + "\n\nÚltimo intento: " + err.Error())
		} else {
			ok++
			if st == "" {
				st = "Al día"
			}
			it.Status = st
		}
		it.Checked = false
		e.done = append(e.done, it.Name)
		id := it.ID
		e.St.WithCfg(func(c *Config) { delete(c.Checked, id) })
		e.ver++
		e.mu.Unlock()
		if err != nil {
			e.Log("err", "✖ %s: %v", it.Name, err)
		} else {
			e.Log("ok", "✔ %s: %s", it.Name, strings.ToLower(st))
		}
	}
	e.St.SaveConfig()
	items := e.Items()
	e.St.SaveItems(items)
	e.mu.Lock()
	switch {
	case fail == 0:
		e.result = fmt.Sprintf("Hecho: %d elemento(s) resuelto(s).", ok)
	case ok == 0:
		e.result = fmt.Sprintf("No se pudo resolver ninguno de los %d elemento(s). Mira el Registro.", fail)
	default:
		e.result = fmt.Sprintf("%d resuelto(s) y %d con error. Mira el Registro.", ok, fail)
	}
	e.busy, e.status, e.prog = false, "Listo.", [2]int{0, 0}
	e.resetProgress()
	e.mu.Unlock()
	e.St.AddScore(Score(items))
	// Se vuelve a comprobar de verdad lo que se ha tocado (versión instalada, espacio que queda,
	// ajuste aplicado), para que lo que se ve nunca se quede con datos viejos.
	cats := map[string]bool{}
	for _, it := range todo {
		cats[it.Category] = true
	}
	var cl []string
	for c := range cats {
		cl = append(cl, c)
	}
	if postRunRefresh {
		go e.RefreshCats(cl...)
	}
}

// postRunRefresh: en las pruebas se apaga (el refresco en segundo plano escribiría después del test).
var postRunRefresh = true

// RefreshCats vuelve a pasar los analizadores de esas categorías en segundo plano.
func (e *Engine) RefreshCats(cats ...string) {
	want := map[string]bool{}
	for _, c := range cats {
		want[c] = true
	}
	var names []string
	for _, s := range e.scanners {
		for _, c := range s.Cats {
			if want[c] {
				names = append(names, s.Name)
				break
			}
		}
	}
	if len(names) > 0 {
		e.refreshWait(names...)
	}
}

// StartupRefresh: al abrir no se bloquea la ventana con un análisis. Si lo guardado tiene
// menos de 'quickAge' no se hace nada; si no, se ponen al día en segundo plano los rápidos
// (y los lentos solo si lo guardado tiene más de 'slowAge').
func (e *Engine) StartupRefresh(age, quickAge, slowAge time.Duration) {
	if age < quickAge {
		return
	}
	var names []string
	for _, s := range e.scanners {
		if !s.Slow || age > slowAge {
			names = append(names, s.Name)
		}
	}
	time.Sleep(4 * time.Second) // que la ventana termine de abrir antes de lanzar nada
	e.refreshWait(names...)
	e.mu.Lock()
	e.lastScan = time.Now()
	e.mu.Unlock()
	e.St.AddScore(Score(e.Items()))
}

// refreshWait es Refresh, pero si ya hay otro refresco en marcha espera a que termine.
func (e *Engine) refreshWait(names ...string) {
	for i := 0; i < 600; i++ {
		e.mu.Lock()
		free := !e.bgUpd && !e.busy
		e.mu.Unlock()
		if free {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	e.Refresh(names...)
}

func (e *Engine) resetProgress() {
	e.phase, e.act, e.running, e.item, e.sub, e.subPct, e.step, e.steps, e.queue = "", "", nil, "", "", -1, 0, 0, nil
}

// runPhase: título general de la tarea (la interfaz lo usa para el rótulo de arriba).
func runPhase(l []*Item) string {
	clean, fix := true, true
	for _, it := range l {
		if it.Action != "clean" {
			clean = false
		}
		if it.Action == "winget" || it.Action == "winupdate" || it.Action == "defsig" {
			fix = false
		}
	}
	switch {
	case clean && len(l) > 0:
		return "clean"
	case fix && len(l) > 0:
		return "fix"
	}
	return "update"
}

// actScene: qué animación toca para cada acción.
func actScene(action string) string {
	switch action {
	case "winget", "defsig":
		return "update"
	case "winupdate":
		return "winupdate"
	case "clean":
		return "clean"
	case "restorepoint":
		return "restore"
	case "":
		return "update"
	}
	return "fix"
}

// Cmd anota una orden que se lanza en segundo plano; Out, una línea de lo que responde.
func (e *Engine) Cmd(format string, a ...any) { e.Log("cmd", "> "+format, a...) }
func (e *Engine) Out(line string)             { e.Log("out", "%s", line) }

// SetSub actualiza la subtarea del elemento en curso ("Descargando 40 MB de 98 MB", 41 %).
// pct < 0 = sin porcentaje conocido.
func (e *Engine) SetSub(text string, pct int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.busy {
		return
	}
	e.sub, e.subPct = text, pct
	if pct >= 0 && e.steps > 0 {
		if pct > 100 {
			pct = 100
		}
		// el porcentaje global nunca retrocede (p. ej. al pasar de "descargando" a "instalando")
		if v := e.step*100 + pct; v > e.prog[0] || e.prog[1] != e.steps*100 {
			e.prog = [2]int{v, e.steps * 100}
		}
	}
}

func needsRestorePoint(l []*Item) bool {
	for _, it := range l {
		switch it.Action {
		case "winget", "smb1", "rdpoff", "svcoff", "uninstall", "pentestfix", "guestoff":
			return true
		}
	}
	return false
}

func runAction(a Action, e *Engine, it *Item) (st string, err error) {
	defer func() {
		if r := recover(); r != nil {
			panicHook("acción "+it.Action+" ("+it.Name+")", r, debug.Stack())
			err = fmt.Errorf("fallo interno: %v", r)
		}
	}()
	return a(e, it)
}

// RunAlt ejecuta la acción alternativa de un elemento (p. ej. "Volver a permitir").
func (e *Engine) RunAlt(id string) string {
	e.mu.Lock()
	it := e.find(id)
	e.mu.Unlock()
	if it == nil || it.Alt == "" {
		return ""
	}
	if it.Alt == "closeupdate" {
		// "Cerrar y actualizar": misma actualización, con ventana de progreso, cerrando antes el programa
		e.SetFlag("cerrar:" + it.ID)
		go e.Run([]string{it.ID})
		return ""
	}
	if it.Alt == "allowupdate" {
		e.RemoveExclusion(it.Arg)
		return "Volverá a avisar de las actualizaciones de " + it.Name + "."
	}
	a, ok := e.alts[it.Alt]
	if !ok {
		return "Esta opción todavía no está disponible."
	}
	st, err := runAction(a, e, it)
	if err != nil {
		return err.Error()
	}
	e.mu.Lock()
	if st != "" {
		it.Status = st
	}
	e.ver++
	e.mu.Unlock()
	return ""
}

func (e *Engine) Dismiss(id string) {
	e.mu.Lock()
	e.St.WithCfg(func(c *Config) { c.Dismissed[id] = true })
	if it := e.find(id); it != nil {
		it.Status, it.Checked = "Oculto", false
	}
	e.ver++
	e.mu.Unlock()
	e.St.SaveConfig()
}

func (e *Engine) DismissedCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	e.St.WithCfg(func(c *Config) { n = len(c.Dismissed) })
	return n
}

func (e *Engine) ResetDismissed() {
	e.mu.Lock()
	e.St.WithCfg(func(c *Config) { c.Dismissed = map[string]bool{} })
	e.mu.Unlock()
	e.St.SaveConfig()
}

func (e *Engine) Exclude(id string) {
	e.mu.Lock()
	it := e.find(id)
	if it != nil && it.Arg != "" {
		arg := it.Arg
		e.St.WithCfg(func(c *Config) { c.Excluded[arg] = true })
		it.Status, it.Checked, it.Alt, it.AltLabel = "Oculto", false, "allowupdate", "Volver a permitir"
		e.ver++
	}
	e.mu.Unlock()
	e.St.SaveConfig()
}

func (e *Engine) RemoveExclusion(wingetID string) {
	e.mu.Lock()
	e.St.WithCfg(func(c *Config) { delete(c.Excluded, wingetID) })
	for _, it := range e.items {
		if it.Arg == wingetID && it.Status == "Oculto" {
			it.Status, it.Alt, it.AltLabel = "Actualizar", "", ""
		}
	}
	e.ver++
	e.mu.Unlock()
	e.St.SaveConfig()
}

// History para la interfaz (con índice, y si se puede deshacer o volver a permitir).
type HistOut struct {
	HistEntry
	Index    int  `json:"index"`
	CanUndo  bool `json:"canUndo"`
	Excluded bool `json:"excluded"`
}

func (e *Engine) History() []HistOut {
	excl := map[string]bool{}
	e.St.WithCfg(func(c *Config) {
		for k, v := range c.Excluded {
			excl[k] = v
		}
	})
	e.St.mu.Lock()
	defer e.St.mu.Unlock()
	out := []HistOut{}
	for i, h := range e.St.Hist {
		out = append(out, HistOut{HistEntry: h, Index: i,
			CanUndo:  h.Result == "OK" && !h.Undone && h.WingetID != "" && h.From != "" && h.From != "-" && h.From != "Unknown",
			Excluded: h.WingetID != "" && excl[h.WingetID]})
	}
	return out
}

// Refresh vuelve a pasar solo algunos analizadores en segundo plano (sin bloquear la ventana).
func (e *Engine) Refresh(names ...string) {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var l []Scanner
	for _, s := range e.scanners {
		if want[s.Name] {
			l = append(l, s)
		}
	}
	e.mu.Lock()
	if e.bgUpd || len(l) == 0 {
		e.mu.Unlock()
		return
	}
	e.bgUpd = true
	e.mu.Unlock()
	e.runScanners(l, false)
	items := e.Items()
	e.St.SaveItems(items)
	e.mu.Lock()
	e.bgUpd = false
	e.ver++
	e.mu.Unlock()
}

var flagsMu sync.Mutex
var flags = map[string]bool{}

func (e *Engine) SetFlag(k string) { flagsMu.Lock(); flags[k] = true; flagsMu.Unlock() }

// TakeFlag devuelve si la marca estaba puesta y la quita.
func (e *Engine) TakeFlag(k string) bool {
	flagsMu.Lock()
	defer flagsMu.Unlock()
	v := flags[k]
	delete(flags, k)
	return v
}
