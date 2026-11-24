//go:build windows

package main

// Diagnóstico y tráfico: contadores de rendimiento (PDH) con nombres en inglés,
// que funcionan igual en Windows en español.

import (
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	pdh                   = windows.NewLazySystemDLL("pdh.dll")
	pPdhOpenQuery         = pdh.NewProc("PdhOpenQueryW")
	pPdhAddEnglishCounter = pdh.NewProc("PdhAddEnglishCounterW")
	pPdhCollectQueryData  = pdh.NewProc("PdhCollectQueryData")
	pPdhGetFormattedArray = pdh.NewProc("PdhGetFormattedCounterArrayW")
	pGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	pGetTickCount64       = kernel32.NewProc("GetTickCount64")
	pGetSystemPowerStatus = kernel32.NewProc("GetSystemPowerStatus")
	psapi                 = windows.NewLazySystemDLL("psapi.dll")
	pGetPerformanceInfo   = psapi.NewProc("GetPerformanceInfo")
)

const pdhFmtDouble = 0x00000200
const pdhFmtNoCap100 = 0x00008000
const pdhMoreData = 0x800007D2

type pdhQuery struct {
	h        uintptr
	counters map[string]uintptr
}

func newQuery(paths map[string]string) *pdhQuery {
	q := &pdhQuery{counters: map[string]uintptr{}}
	if r, _, _ := pPdhOpenQuery.Call(0, 0, uintptr(unsafe.Pointer(&q.h))); r != 0 {
		return nil
	}
	for k, p := range paths {
		var c uintptr
		pp, _ := windows.UTF16PtrFromString(p)
		if r, _, _ := pPdhAddEnglishCounter.Call(q.h, uintptr(unsafe.Pointer(pp)), 0, uintptr(unsafe.Pointer(&c))); r == 0 {
			q.counters[k] = c
		}
	}
	pPdhCollectQueryData.Call(q.h)
	return q
}

type pdhItem struct {
	name *uint16
	_    uint32
	_    uint32 // alineación
	val  float64
}

// values devuelve instancia → valor de un contador con comodín.
func (q *pdhQuery) values(k string) map[string]float64 {
	c, ok := q.counters[k]
	if !ok {
		return nil
	}
	var size, count uint32
	r, _, _ := pPdhGetFormattedArray.Call(c, pdhFmtDouble|pdhFmtNoCap100, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), 0)
	if uint32(r) != pdhMoreData || size == 0 {
		return nil
	}
	buf := make([]byte, size)
	r, _, _ = pPdhGetFormattedArray.Call(c, pdhFmtDouble|pdhFmtNoCap100, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&buf[0])))
	if r != 0 {
		return nil
	}
	out := map[string]float64{}
	// PDH_FMT_COUNTERVALUE_ITEM_W: LPWSTR szName; PDH_FMT_COUNTERVALUE{DWORD CStatus; double} → 24 bytes en 64 bits
	for i := uint32(0); i < count; i++ {
		base := unsafe.Pointer(&buf[uintptr(i)*24])
		name := windows.UTF16PtrToString(*(**uint16)(base))
		status := *(*uint32)(unsafe.Add(base, 8))
		v := *(*float64)(unsafe.Add(base, 16))
		if status == 0 || status == 1 {
			// nombres repetidos (varios procesos iguales) → se suman
			out[name] += v
		}
	}
	return out
}

func (q *pdhQuery) total(k string) float64 {
	s := 0.0
	for _, v := range q.values(k) {
		s += v
	}
	return s
}

func (q *pdhQuery) one(k, inst string) float64 { return q.values(k)[inst] }

// ---------- recolector ----------

type DiagPoint struct {
	T  int64     `json:"t"`
	C  float64   `json:"c"`
	M  float64   `json:"m"`
	DA float64   `json:"da"`
	DR float64   `json:"dr"`
	DW float64   `json:"dw"`
	DL float64   `json:"dl"`
	NR float64   `json:"nr"`
	NS float64   `json:"ns"`
	F  float64   `json:"f"`
	G  float64   `json:"g"`
	GM float64   `json:"gm"`
	CK float64   `json:"ck"`
	CM float64   `json:"cm"`
	CA float64   `json:"ca"`
	PG float64   `json:"pg"`
	K  []float64 `json:"k,omitempty"` // uso de cada núcleo
}

type diagProc struct {
	N   string  `json:"n"`
	PID int     `json:"pid"`
	C   float64 `json:"c"`
	PV  float64 `json:"pv"`
	WS  float64 `json:"ws"`
	IO  float64 `json:"io"`
	TH  float64 `json:"th"`
	H   float64 `json:"h"`
}

type diagDisk struct {
	N     string  `json:"n"`
	Kind  string  `json:"kind"`
	Model string  `json:"model"`
	A     float64 `json:"a"`
	R     float64 `json:"r"`
	W     float64 `json:"w"`
	L     float64 `json:"l"`
	Free  uint64  `json:"free"`
	Size  uint64  `json:"size"`
}

type diagNic struct {
	N  string  `json:"n"`
	R  float64 `json:"r"`
	S  float64 `json:"s"`
	BW float64 `json:"bw"`
}

type Collector struct {
	mu      sync.Mutex
	q       *pdhQuery
	pts     []DiagPoint
	cores   []float64
	procs   []diagProc
	disks   []diagDisk
	nics    []diagNic
	info    map[string]any
	baseMHz float64
	lastUse time.Time
	running bool
}

var collector = &Collector{}

// HostInfoPath: dónde se guarda la ficha del equipo (la pone main). Se lee al momento y
// se vuelve a generar en segundo plano si tiene más de 3 días.
var HostInfoPath string
var infoLoading bool

func (c *Collector) ensureInfo() {
	c.mu.Lock()
	if c.info != nil || infoLoading {
		c.mu.Unlock()
		return
	}
	infoLoading = true
	c.mu.Unlock()
	set := func(info map[string]any) {
		c.mu.Lock()
		c.info = info
		if v, ok := info["baseMHz"].(float64); ok {
			c.baseMHz = v
		}
		c.mu.Unlock()
	}
	var cached map[string]any
	fresh := false
	if HostInfoPath != "" {
		if fi, err := os.Stat(HostInfoPath); err == nil && readJSON(HostInfoPath, &cached) == nil && len(cached) > 2 {
			set(cached)
			fresh = time.Since(fi.ModTime()) < 72*time.Hour
		}
	}
	if fresh {
		return
	}
	go func() {
		info := loadHostInfo()
		set(info)
		if HostInfoPath != "" && len(info) > 2 {
			_ = writeJSON(HostInfoPath, info)
		}
	}()
}

// HostInfo: ficha del equipo para Hardware (sin esperar si ya está en caché).
func HostInfo() map[string]any {
	collector.ensureInfo()
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.info == nil {
		return map[string]any{"ready": false}
	}
	out := map[string]any{}
	for k, v := range collector.info {
		out[k] = v
	}
	return out
}

var perfPaths = map[string]string{
	"cpu":    `\Processor(_Total)\% Processor Time`,
	"cpuk":   `\Processor(_Total)\% Privileged Time`,
	"mcom":   `\Memory\Committed Bytes`,
	"mcache": `\Memory\Cache Bytes`,
	"mpages": `\Memory\Pages/sec`,
	"cores":  `\Processor(*)\% Processor Time`,
	"perf":   `\Processor Information(_Total)\% Processor Performance`,
	"dtime":  `\PhysicalDisk(*)\% Idle Time`,
	"dread":  `\PhysicalDisk(*)\Disk Read Bytes/sec`,
	"dwrite": `\PhysicalDisk(*)\Disk Write Bytes/sec`,
	"dlat":   `\PhysicalDisk(*)\Avg. Disk sec/Transfer`,
	"nrecv":  `\Network Interface(*)\Bytes Received/sec`,
	"nsent":  `\Network Interface(*)\Bytes Sent/sec`,
	"nbw":    `\Network Interface(*)\Current Bandwidth`,
	"gpu":    `\GPU Engine(*)\Utilization Percentage`,
	"gmem":   `\GPU Adapter Memory(*)\Dedicated Usage`,
	"pcpu":   `\Process(*)\% Processor Time`,
	"ppriv":  `\Process(*)\Private Bytes`,
	"pws":    `\Process(*)\Working Set - Private`,
	"pio":    `\Process(*)\IO Data Bytes/sec`,
	"pth":    `\Process(*)\Thread Count`,
	"phd":    `\Process(*)\Handle Count`,
	"ppid":   `\Process(*)\ID Process`,
}

// touch arranca el muestreo (si no estaba) y lo mantiene vivo mientras se use.
func (c *Collector) touch() {
	c.mu.Lock()
	c.lastUse = time.Now()
	if c.running {
		c.mu.Unlock()
		return
	}
	c.running = true
	c.mu.Unlock()
	go c.loop()
}

func (c *Collector) loop() {
	q := newQuery(perfPaths)
	c.mu.Lock()
	c.q = q
	c.mu.Unlock()
	c.ensureInfo() // en paralelo: las gráficas empiezan al momento
	if q == nil {
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
		return
	}
	tick := 0
	for {
		time.Sleep(time.Second)
		pPdhCollectQueryData.Call(q.h)
		c.sample(q, tick%3 == 0)
		tick++
		c.mu.Lock()
		idle := time.Since(c.lastUse) > 45*time.Second
		if idle {
			c.running = false
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
	}
}

func (c *Collector) sample(q *pdhQuery, heavy bool) {
	p := DiagPoint{T: time.Now().UnixMilli(), C: q.one("cpu", "_Total"), G: -1}
	if p.C == 0 {
		p.C = q.total("cpu")
	}
	var ms memStatus
	ms.len = uint32(unsafe.Sizeof(ms))
	pGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	p.M = float64(ms.total - ms.avail)
	p.CK = clamp(q.total("cpuk"), 0, 100)
	p.CM, p.CA, p.PG = q.total("mcom"), q.total("mcache"), q.total("mpages")
	if pf := q.one("perf", "_Total"); pf > 0 && c.baseMHz > 0 {
		p.F = c.baseMHz * pf / 100
	}
	for k, v := range q.values("dtime") {
		if k != "_Total" {
			p.DA = max(p.DA, clamp(100-v, 0, 100))
		}
	}
	p.DR = q.one("dread", "_Total")
	p.DW = q.one("dwrite", "_Total")
	p.DL = q.one("dlat", "_Total") * 1000
	recv, sent, bw := q.values("nrecv"), q.values("nsent"), q.values("nbw")
	for k, v := range recv {
		if !virtualNic(k) {
			p.NR += v * 8
		}
	}
	for k, v := range sent {
		if !virtualNic(k) {
			p.NS += v * 8
		}
	}
	if g := q.values("gpu"); len(g) > 0 {
		per := map[string]float64{}
		for k, v := range g {
			if strings.Contains(k, "engtype_3D") {
				per["3d"] += v
			}
		}
		p.G = clamp(per["3d"], 0, 100)
	}
	p.GM = q.total("gmem")

	cv := q.values("cores")
	keys := []string{}
	for k := range cv {
		if k != "_Total" {
			keys = append(keys, k)
		}
	}
	// "0", "1"… o "0,0", "0,1"… según la versión de Windows: se ordena por números
	sort.Slice(keys, func(a, b int) bool { return CompareVersions(keys[a], keys[b]) < 0 })
	cores := make([]float64, 0, len(keys))
	for _, k := range keys {
		cores = append(cores, round1(clamp(cv[k], 0, 100)))
	}
	p.K = cores

	c.mu.Lock()
	defer c.mu.Unlock()
	c.pts = append(c.pts, p)
	if len(c.pts) > 3700 {
		c.pts = c.pts[len(c.pts)-3600:]
	}
	c.cores = cores
	nics := []diagNic{}
	for k, v := range recv {
		if virtualNic(k) {
			continue
		}
		nics = append(nics, diagNic{N: k, R: v * 8, S: sent[k] * 8, BW: bw[k]})
	}
	sort.Slice(nics, func(a, b int) bool { return nics[a].R+nics[a].S > nics[b].R+nics[b].S })
	c.nics = nics
	if heavy {
		c.procs = procTable(q)
		c.disks = diskTable(q)
	}
}

func virtualNic(n string) bool {
	l := strings.ToLower(n)
	return hasAny(l, "loopback", "isatap", "teredo", "6to4", "pseudo", "wan miniport", "kernel debug")
}

func clamp(v, a, b float64) float64 {
	if v < a {
		return a
	}
	if v > b {
		return b
	}
	return v
}

func procTable(q *pdhQuery) []diagProc {
	pid := q.values("ppid")
	cpu, priv, ws, io, th, hd := q.values("pcpu"), q.values("ppriv"), q.values("pws"), q.values("pio"), q.values("pth"), q.values("phd")
	ncpu := float64(numCPU())
	out := []diagProc{}
	for k, id := range pid {
		if k == "_Total" || k == "Idle" {
			continue
		}
		out = append(out, diagProc{N: strings.SplitN(k, "#", 2)[0], PID: int(id), C: clamp(cpu[k]/ncpu, 0, 100), PV: priv[k], WS: ws[k], IO: io[k], TH: th[k], H: hd[k]})
	}
	return out
}

func diskTable(q *pdhQuery) []diagDisk {
	idle, rd, wr, lat := q.values("dtime"), q.values("dread"), q.values("dwrite"), q.values("dlat")
	out := []diagDisk{}
	for k, v := range idle {
		if k == "_Total" {
			continue
		}
		d := diagDisk{N: k, A: clamp(100-v, 0, 100), R: rd[k], W: wr[k], L: lat[k] * 1000}
		// "0 C: D:" → espacio libre de la primera letra
		for _, f := range strings.Fields(k) {
			if len(f) == 2 && f[1] == ':' {
				fr, tot := diskFree(f + `\`)
				d.Free += fr
				d.Size += tot
			}
		}
		out = append(out, d)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].N < out[b].N })
	return out
}

type memStatus struct {
	len, load                    uint32
	total, avail, ptotal, pavail uint64
	vtotal, vavail, vextended    uint64
}

type perfInfo struct {
	cb                                                                   uint32
	commitTotal, commitLimit, commitPeak, physTotal, physAvail, sysCache uintptr
	kernelTotal, kernelPaged, kernelNonpaged, pageSize                   uintptr
	handles, procs, threads                                              uint32
}

func numCPU() int {
	n, _ := strconv.Atoi(os.Getenv("NUMBER_OF_PROCESSORS"))
	if n < 1 {
		n = 1
	}
	return n
}

func loadHostInfo() map[string]any {
	info, err := psObj[map[string]any](`$c=Get-CimInstance Win32_Processor
$c1=$c | Select-Object -First 1
$o=@{ready=$true;cpu=([string]$c1.Name).Trim();baseMHz=[double]$c1.MaxClockSpeed;cores=[int]($c|Measure-Object NumberOfCores -Sum).Sum;threads=[int]($c|Measure-Object NumberOfLogicalProcessors -Sum).Sum;sockets=@($c).Count;l2=[int64]$c1.L2CacheSize;l3=[int64]$c1.L3CacheSize;virt=[bool]$c1.VirtualizationFirmwareEnabled}
$cs=Get-CimInstance Win32_ComputerSystem; $o.board=(([string]$cs.Manufacturer)+' '+([string]$cs.Model)).Trim()
$os=Get-CimInstance Win32_OperatingSystem; $o.os=([string]$os.Caption)+' ('+([string]$os.Version)+')'; $o.boot=$os.LastBootUpTime.ToString('o')
$mt=@{20='DDR';21='DDR2';24='DDR3';26='DDR4';29='LPDDR3';30='LPDDR4';34='DDR5';35='LPDDR5'}
$o.modules=@(Get-CimInstance Win32_PhysicalMemory | ForEach-Object{ @{bank=([string]$_.DeviceLocator).Trim();size=[int64]$_.Capacity;speed=[int]$_.ConfiguredClockSpeed;maker=([string]$_.Manufacturer).Trim();part=([string]$_.PartNumber).Trim()} })
$pm=Get-CimInstance Win32_PhysicalMemory | Select-Object -First 1; if($pm){ $o.memType=$mt[[int]$pm.SMBIOSMemoryType]; $o.memSpeed=[int]$pm.ConfiguredClockSpeed }
$o.slots=[int](Get-CimInstance Win32_PhysicalMemoryArray | Measure-Object MemoryDevices -Sum).Sum
$o.gpus=@(Get-CimInstance Win32_VideoController | ForEach-Object{@{name=[string]$_.Name;driver=[string]$_.DriverVersion}})
$o.disks=@(Get-PhysicalDisk | ForEach-Object{@{name=[string]$_.FriendlyName;media=[string]$_.MediaType;bus=[string]$_.BusType;health=[string]$_.HealthStatus;size=[int64]$_.Size}})
$o.nics=@(Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object{@{name=[string]$_.Name;desc=[string]$_.InterfaceDescription;speed=[string]$_.LinkSpeed}})
$o | ConvertTo-Json -Depth 4 -Compress`, time.Minute)
	if err != nil || info == nil {
		info = map[string]any{"ready": true}
	}
	var ms memStatus
	ms.len = uint32(unsafe.Sizeof(ms))
	pGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	info["memTotal"] = ms.total
	return info
}

type powerStatus struct {
	ac, flag, pct, saver byte
	life, full           uint32
}

// Diag devuelve lo que pide la página de Diagnóstico.
func Diag(rangeSec int, since int64) map[string]any {
	c := collector
	c.touch()
	c.mu.Lock()
	defer c.mu.Unlock()
	from := time.Now().Add(-time.Duration(rangeSec) * time.Second).UnixMilli()
	if since > from {
		from = since + 1
	}
	pts := []DiagPoint{}
	for _, p := range c.pts {
		if p.T >= from {
			pts = append(pts, p)
		}
	}
	// rangos largos: se reduce a unos 400 puntos
	if len(pts) > 600 {
		step := len(pts) / 400
		red := []DiagPoint{}
		for i := 0; i < len(pts); i += step {
			red = append(red, pts[i])
		}
		pts = red
	}
	var ms memStatus
	ms.len = uint32(unsafe.Sizeof(ms))
	pGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	var pi perfInfo
	pi.cb = uint32(unsafe.Sizeof(pi))
	pGetPerformanceInfo.Call(uintptr(unsafe.Pointer(&pi)), uintptr(pi.cb))
	up, _, _ := pGetTickCount64.Call()
	out := map[string]any{
		"now":    time.Now().UnixMilli(),
		"points": pts,
		"info":   ternary(c.info != nil, c.info, map[string]any{"ready": false}),
		"mem": map[string]any{"total": ms.total, "avail": ms.avail, "commit": uint64(pi.commitTotal) * uint64(pi.pageSize), "limit": uint64(pi.commitLimit) * uint64(pi.pageSize),
			"cache": uint64(pi.sysCache) * uint64(pi.pageSize), "paged": uint64(pi.kernelPaged) * uint64(pi.pageSize), "nonpaged": uint64(pi.kernelNonpaged) * uint64(pi.pageSize),
			"pagefile": int64(uint64(pi.commitLimit)*uint64(pi.pageSize)) - int64(ms.total)},
		"sys":   map[string]any{"uptime": up / 1000, "procs": pi.procs, "threads": pi.threads, "handles": pi.handles, "logical": numCPU()},
		"cores": c.cores,
		"procs": c.procs,
		"disks": c.disks,
		"nics":  c.nics,
	}
	var ps powerStatus
	if r, _, _ := pGetSystemPowerStatus.Call(uintptr(unsafe.Pointer(&ps))); r != 0 && ps.flag != 128 && ps.flag != 255 && ps.pct <= 100 {
		minLeft := -1
		if ps.life != 0xFFFFFFFF {
			minLeft = int(ps.life / 60)
		}
		out["battery"] = map[string]any{"pct": ps.pct, "ac": ps.ac == 1, "charging": ps.flag&8 != 0, "min": minLeft}
	}
	out["insights"] = insights(c.pts, ms, c.procs)
	return out
}

func insights(pts []DiagPoint, ms memStatus, procs []diagProc) []map[string]string {
	var l []map[string]string
	add := func(level, title, detail string) {
		l = append(l, map[string]string{"level": level, "title": title, "detail": detail})
	}
	n := len(pts)
	if n == 0 {
		return []map[string]string{{"level": "info", "title": "Recogiendo datos…", "detail": "En unos segundos aparecerá el diagnóstico."}}
	}
	w := pts
	if n > 60 {
		w = pts[n-60:]
	}
	var c, da, dl float64
	for _, p := range w {
		c += p.C
		da += p.DA
		dl += p.DL
	}
	k := float64(len(w))
	c, da, dl = c/k, da/k, dl/k
	top := func(f func(diagProc) float64) string {
		cp := append([]diagProc{}, procs...)
		sort.Slice(cp, func(a, b int) bool { return f(cp[a]) > f(cp[b]) })
		if len(cp) == 0 {
			return ""
		}
		return cp[0].N
	}
	memPct := 0.0
	if ms.total > 0 {
		memPct = float64(ms.total-ms.avail) / float64(ms.total) * 100
	}
	if c > 85 {
		add("bad", "El procesador va al límite", "Media del último minuto: "+strconv.Itoa(int(c))+" %. El que más consume ahora es "+top(func(p diagProc) float64 { return p.C })+".")
	} else if c > 60 {
		add("warn", "Procesador bastante ocupado", "Media del último minuto: "+strconv.Itoa(int(c))+" %.")
	}
	if memPct > 90 {
		add("bad", "Memoria casi llena", "Windows está usando el disco como memoria y todo va más lento. Lo que más ocupa: "+top(func(p diagProc) float64 { return p.PV })+".")
	} else if memPct > 80 {
		add("warn", "Memoria alta", "Se usa el "+strconv.Itoa(int(memPct))+" % de la RAM.")
	}
	if da > 90 && dl > 50 {
		add("bad", "El disco no da abasto", "Está ocupado casi todo el tiempo y tarda "+strconv.Itoa(int(dl))+" ms en responder. Si es un disco mecánico, cambiarlo por un SSD es la mejora más notable.")
	} else if dl > 100 {
		add("warn", "El disco responde lento", "Tarda "+strconv.Itoa(int(dl))+" ms de media en cada operación.")
	}
	if len(l) == 0 {
		add("ok", "Todo con holgura", "Ni el procesador, ni la memoria, ni el disco están limitando el equipo ahora mismo.")
	}
	return l
}

// ---------- tráfico ----------

var dnsCache sync.Map // ip → host ("" mientras se busca)

func lookupHost(ip string) string {
	if v, ok := dnsCache.Load(ip); ok {
		return v.(string)
	}
	dnsCache.Store(ip, "")
	go func() {
		names, err := net.LookupAddr(ip)
		if err == nil && len(names) > 0 {
			dnsCache.Store(ip, strings.TrimSuffix(names[0], "."))
		}
	}()
	return ""
}

var (
	ownerCache sync.Map // ip → [2]string{org, cc}
	connSeen   = map[string]int64{}
	connSeenMu sync.Mutex
	pathCache  sync.Map // pid → [2]string{nombre, ruta}
)

// ipOwner: dueño y país de una IP pública (Team Cymru por DNS, en segundo plano y en caché).
func ipOwner(ip string) (string, string) {
	if v, ok := ownerCache.Load(ip); ok {
		x := v.([2]string)
		return x[0], x[1]
	}
	ownerCache.Store(ip, [2]string{})
	go func() {
		q := CymruQuery(ip)
		if q == "" {
			return
		}
		txt, err := net.LookupTXT(q)
		if err != nil || len(txt) == 0 {
			return
		}
		asn, cc := ParseCymruOrigin(txt[0])
		org := ""
		if asn != "" {
			if t2, err := net.LookupTXT("AS" + asn + ".asn.cymru.com"); err == nil && len(t2) > 0 {
				org = ParseCymruAS(t2[0])
			}
		}
		ownerCache.Store(ip, [2]string{org, cc})
	}()
	return "", ""
}

// procPath: ruta del ejecutable de un proceso (en caché mientras siga el mismo nombre).
func procPath(pid int, name string) string {
	if v, ok := pathCache.Load(pid); ok {
		x := v.([2]string)
		if x[0] == name {
			return x[1]
		}
	}
	p := ""
	if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)); err == nil {
		buf := make([]uint16, 1024)
		n := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
			p = windows.UTF16ToString(buf[:n])
		}
		windows.CloseHandle(h)
	}
	pathCache.Store(pid, [2]string{name, p})
	return p
}

func Traffic() TrafficOut {
	collector.touch()
	names := map[int]string{}
	for _, p := range snapProcs(false) { // solo nombres: barato
		names[p.PID] = p.Name
	}
	conns := NetConns(false)
	listen := map[int]bool{}
	for _, c := range conns {
		if c.State == "Listen" {
			listen[c.LPort] = true
		}
	}
	me := os.Getpid()
	exe, _ := os.Executable()
	out := TrafficOut{Conns: []Conn{}, Hist: []TPoint{}}
	seen := map[int]bool{}
	now := time.Now().UnixMilli()
	connSeenMu.Lock()
	live := map[string]bool{}
	for _, c := range conns {
		if c.State == "Listen" {
			out.Listen++
			continue
		}
		if c.State == "" || c.RAddr == "0.0.0.0" || c.RAddr == "::" || c.PID == 0 || c.PID == me {
			continue
		}
		name := names[c.PID]
		path := procPath(c.PID, name)
		if exe != "" && strings.EqualFold(path, exe) {
			continue
		}
		x := Conn{Proc: ternary(name != "", strings.TrimSuffix(name, ".exe"), "PID "+strconv.Itoa(c.PID)), Path: path, PID: c.PID, Proto: "TCP",
			Local: net.JoinHostPort(c.LAddr, strconv.Itoa(c.LPort)), Remote: net.JoinHostPort(c.RAddr, strconv.Itoa(c.RPort)), State: stateES(c.State),
			IPv6: strings.Contains(c.RAddr, ":"), Dir: "sale"}
		ClassifyConn(&x, c.RAddr, c.RPort)
		if listen[c.LPort] && c.LPort < 49152 {
			x.Dir = "entra"
			x.Svc = ternary(svcNames[c.LPort] != "", svcNames[c.LPort], "puerto "+strconv.Itoa(c.LPort)) + " (entrante)"
			x.SvcCat = SvcCategory(c.LPort)
		} else {
			x.SvcCat = SvcCategory(c.RPort)
		}
		x.Cat = AppCategory(x.Proc, path)
		if x.Scope == "Internet" {
			x.Host = lookupHost(c.RAddr)
			x.Org, x.CC = ipOwner(c.RAddr)
			out.Internet++
		}
		key := strconv.Itoa(c.PID) + "|" + x.Local + "|" + x.Remote
		live[key] = true
		if t, ok := connSeen[key]; ok {
			x.Since = t
		} else {
			connSeen[key] = now
			x.Since = now
		}
		seen[c.PID] = true
		out.Conns = append(out.Conns, x)
	}
	for k := range connSeen {
		if !live[k] {
			delete(connSeen, k)
		}
	}
	connSeenMu.Unlock()
	sort.SliceStable(out.Conns, func(a, b int) bool {
		ra, rb := out.Conns[a].Risk != "", out.Conns[b].Risk != ""
		if ra != rb {
			return ra
		}
		return strings.ToLower(out.Conns[a].Proc) < strings.ToLower(out.Conns[b].Proc)
	})
	out.Procs = len(seen)
	collector.mu.Lock()
	n := len(collector.pts)
	from := n - 120
	if from < 0 {
		from = 0
	}
	for _, p := range collector.pts[from:] {
		tp := TPoint{T: p.T, In: p.NR / 8, Out: p.NS / 8}
		out.Hist = append(out.Hist, tp)
		if tp.In > out.PeakIn {
			out.PeakIn = tp.In
		}
		if tp.Out > out.PeakOut {
			out.PeakOut = tp.Out
		}
	}
	if n > 0 {
		out.InBps, out.OutBps = collector.pts[n-1].NR/8, collector.pts[n-1].NS/8
	}
	collector.mu.Unlock()
	return out
}

func stateES(s string) string {
	return map[string]string{"Established": "Conectada", "TimeWait": "Cerrándose", "CloseWait": "Cerrándose", "SynSent": "Conectando", "FinWait1": "Cerrándose", "FinWait2": "Cerrándose", "LastAck": "Cerrándose", "Closing": "Cerrándose", "SynReceived": "Conectando"}[s]
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }
