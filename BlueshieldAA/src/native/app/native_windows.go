//go:build windows

package main

// Consultas al sistema con las funciones nativas de Windows (las mismas que usan el
// Administrador de tareas o netstat) en lugar de lanzar PowerShell. Más rápido y sin crear
// procesos hijo cada pocos segundos, que es justo lo que hace sospechar a los antivirus.

import (
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi              = windows.NewLazySystemDLL("iphlpapi.dll")
	pGetExtendedTcpTable  = iphlpapi.NewProc("GetExtendedTcpTable")
	pGetExtendedUdpTable  = iphlpapi.NewProc("GetExtendedUdpTable")
	pGetProcessMemoryInfo = psapi.NewProc("GetProcessMemoryInfo")
)

// ---------- conexiones (como netstat -ano) ----------

type nConn struct {
	Proto string
	LAddr string
	LPort int
	RAddr string
	RPort int
	State string
	PID   int
}

var tcpStates = map[uint32]string{1: "Closed", 2: "Listen", 3: "SynSent", 4: "SynReceived", 5: "Established", 6: "FinWait1", 7: "FinWait2", 8: "CloseWait", 9: "Closing", 10: "LastAck", 11: "TimeWait", 12: "DeleteTCB"}

func ntohs(p uint32) int { return int((p&0xff)<<8 | (p>>8)&0xff) }

func ip4(a uint32) string { return net.IPv4(byte(a), byte(a>>8), byte(a>>16), byte(a>>24)).String() }

func getTable(proc *windows.LazyProc, af uint32, class uint32) []byte {
	var size uint32
	proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(af), uintptr(class), 0)
	for i := 0; i < 4 && size > 0; i++ {
		buf := make([]byte, size+4096)
		size = uint32(len(buf))
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(af), uintptr(class), 0)
		if r == 0 {
			return buf[:size]
		}
		if r != 122 { // ERROR_INSUFFICIENT_BUFFER
			return nil
		}
	}
	return nil
}

func u32(b []byte, off int) uint32 {
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

// NetConns: todas las conexiones TCP (v4 y v6) y, si udp, los puertos UDP abiertos.
func NetConns(udp bool) []nConn {
	var out []nConn
	if b := getTable(pGetExtendedTcpTable, 2, 5); len(b) >= 4 { // AF_INET, TCP_TABLE_OWNER_PID_ALL
		n := int(u32(b, 0))
		for i := 0; i < n && 4+(i+1)*24 <= len(b); i++ {
			o := 4 + i*24
			out = append(out, nConn{Proto: "TCP", State: tcpStates[u32(b, o)], LAddr: ip4(u32(b, o+4)), LPort: ntohs(u32(b, o+8)), RAddr: ip4(u32(b, o+12)), RPort: ntohs(u32(b, o+16)), PID: int(u32(b, o+20))})
		}
	}
	if b := getTable(pGetExtendedTcpTable, 23, 5); len(b) >= 4 { // AF_INET6
		n := int(u32(b, 0))
		for i := 0; i < n && 4+(i+1)*56 <= len(b); i++ {
			o := 4 + i*56
			out = append(out, nConn{Proto: "TCP", LAddr: net.IP(b[o : o+16]).String(), LPort: ntohs(u32(b, o+20)), RAddr: net.IP(b[o+24 : o+40]).String(), RPort: ntohs(u32(b, o+44)), State: tcpStates[u32(b, o+48)], PID: int(u32(b, o+52))})
		}
	}
	if !udp {
		return out
	}
	if b := getTable(pGetExtendedUdpTable, 2, 1); len(b) >= 4 { // UDP_TABLE_OWNER_PID
		n := int(u32(b, 0))
		for i := 0; i < n && 4+(i+1)*12 <= len(b); i++ {
			o := 4 + i*12
			out = append(out, nConn{Proto: "UDP", LAddr: ip4(u32(b, o)), LPort: ntohs(u32(b, o+4)), PID: int(u32(b, o+8))})
		}
	}
	if b := getTable(pGetExtendedUdpTable, 23, 1); len(b) >= 4 {
		n := int(u32(b, 0))
		for i := 0; i < n && 4+(i+1)*28 <= len(b); i++ {
			o := 4 + i*28
			out = append(out, nConn{Proto: "UDP", LAddr: net.IP(b[o : o+16]).String(), LPort: ntohs(u32(b, o+20)), PID: int(u32(b, o+24))})
		}
	}
	return out
}

// ---------- procesos ----------

type nProc struct {
	PID   int
	PPID  int
	Name  string
	Path  string
	User  string
	Mem   int64
	Start time.Time
	Cmd   string
}

type procMemCounters struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSet, workingSet uintptr
	qpp, qp, qpnp, qnp, pf     uintptr
	peakPF                     uintptr
}

var userCache sync.Map // SID → "DOMINIO\usuario"

func procUser(h windows.Handle) string {
	var tok windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok) != nil {
		return ""
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	sid := tu.User.Sid.String()
	if v, ok := userCache.Load(sid); ok {
		return v.(string)
	}
	acc, dom, _, err := tu.User.Sid.LookupAccount("")
	name := sid
	if err == nil {
		name = dom + `\` + acc
	}
	userCache.Store(sid, name)
	return name
}

// procCmdLine lee la línea de órdenes (Windows 8.1 o posterior).
func procCmdLine(h windows.Handle) string {
	var size uint32
	_ = windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, nil, 0, &size)
	if size == 0 || size > 1<<20 {
		return ""
	}
	buf := make([]byte, size)
	if windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, unsafe.Pointer(&buf[0]), size, &size) != nil {
		return ""
	}
	us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
	return us.String()
}

// ProcList: lista de procesos con ruta, usuario, memoria, inicio y (si cmd) línea de órdenes.
func ProcList(withCmd bool) []nProc {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []nProc
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		p := nProc{PID: int(e.ProcessID), PPID: int(e.ParentProcessID), Name: windows.UTF16ToString(e.ExeFile[:])}
		if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, e.ProcessID); err == nil {
			buf := make([]uint16, 1024)
			n := uint32(len(buf))
			if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
				p.Path = windows.UTF16ToString(buf[:n])
			}
			p.User = procUser(h)
			var mc procMemCounters
			mc.cb = uint32(unsafe.Sizeof(mc))
			if r, _, _ := pGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&mc)), uintptr(mc.cb)); r != 0 {
				p.Mem = int64(mc.workingSet)
			}
			var c, x, k, u windows.Filetime
			if windows.GetProcessTimes(h, &c, &x, &k, &u) == nil {
				p.Start = time.Unix(0, c.Nanoseconds())
			}
			if withCmd {
				p.Cmd = procCmdLine(h)
			}
			windows.CloseHandle(h)
		}
		out = append(out, p)
	}
	return out
}

func KillPID(pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}

// ---------- datos del archivo: empresa, descripción y firma ----------

type fileMeta struct {
	Company, Desc, Product string
	Signed, Signer         string
}

var metaCache sync.Map // ruta|fecha → fileMeta

func verString(block []byte, lang, key string) string {
	var p unsafe.Pointer
	var n uint32
	if windows.VerQueryValue(unsafe.Pointer(&block[0]), `\StringFileInfo\`+lang+`\`+key, unsafe.Pointer(&p), &n) != nil || n == 0 {
		return ""
	}
	return strings.TrimSpace(windows.UTF16PtrToString((*uint16)(p)))
}

func versionInfo(path string) (company, desc, product string) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 {
		return
	}
	block := make([]byte, size)
	if windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&block[0])) != nil {
		return
	}
	langs := []string{"040904b0", "040904e4", "0c0a04b0", "000004b0"}
	var tp unsafe.Pointer
	var tn uint32
	if windows.VerQueryValue(unsafe.Pointer(&block[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&tp), &tn) == nil && tn >= 4 {
		w := (*[2]uint16)(tp)
		langs = append([]string{strings.ToLower(hex4(w[0]) + hex4(w[1]))}, langs...)
	}
	for _, l := range langs {
		if company == "" {
			company = verString(block, l, "CompanyName")
		}
		if desc == "" {
			desc = verString(block, l, "FileDescription")
		}
		if product == "" {
			product = verString(block, l, "ProductName")
		}
	}
	return
}

func hex4(v uint16) string {
	const h = "0123456789abcdef"
	return string([]byte{h[v>>12&0xf], h[v>>8&0xf], h[v>>4&0xf], h[v&0xf]})
}

// verifySig comprueba la firma Authenticode del archivo (sin conexión a Internet).
func verifySig(path string) string {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	fi := &windows.WinTrustFileInfo{FilePath: p}
	fi.Size = uint32(unsafe.Sizeof(*fi))
	data := &windows.WinTrustData{UIChoice: windows.WTD_UI_NONE, RevocationChecks: windows.WTD_REVOKE_NONE, UnionChoice: windows.WTD_CHOICE_FILE,
		StateAction: windows.WTD_STATEACTION_VERIFY, FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fi)}
	data.Size = uint32(unsafe.Sizeof(*data))
	err = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if err == nil {
		return "Firmado"
	}
	if e, ok := err.(windows.Errno); ok && uint32(e) == 0x800B0100 { // TRUST_E_NOSIGNATURE
		return "Sin firmar"
	}
	return "Firma no válida"
}

// FileMeta: empresa, descripción y estado de la firma (en caché por ruta y fecha).
func FileMeta(path string) fileMeta {
	if path == "" {
		return fileMeta{}
	}
	key := path
	if st, err := statMod(path); err == nil {
		key += "|" + st
	}
	if v, ok := metaCache.Load(key); ok {
		return v.(fileMeta)
	}
	m := fileMeta{}
	m.Company, m.Desc, m.Product = versionInfo(path)
	m.Signed = verifySig(path)
	lp := strings.ToLower(path)
	ms := strings.Contains(strings.ToLower(m.Company), "microsoft")
	// muchos archivos de Windows están firmados por catálogo, no dentro del propio archivo
	if m.Signed == "Sin firmar" && ms && (strings.Contains(lp, `\windows\`) || strings.Contains(lp, `\windowsapps\`)) {
		m.Signed = "Microsoft"
	} else if m.Signed == "Firmado" && ms {
		m.Signed = "Microsoft"
	}
	if m.Signed == "Firmado" || m.Signed == "Microsoft" {
		m.Signer = m.Company
	}
	metaCache.Store(key, m)
	return m
}

func statMod(p string) (string, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	return fi.ModTime().UTC().Format(time.RFC3339Nano), nil
}
