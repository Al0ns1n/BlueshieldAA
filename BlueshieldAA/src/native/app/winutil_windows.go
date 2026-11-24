//go:build windows

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	comdlg32 = windows.NewLazySystemDLL("comdlg32.dll")
	ole32    = windows.NewLazySystemDLL("ole32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	pShellExecuteW       = shell32.NewProc("ShellExecuteW")
	pSHBrowseForFolderW  = shell32.NewProc("SHBrowseForFolderW")
	pSHGetPathFromIDList = shell32.NewProc("SHGetPathFromIDListW")
	pGetOpenFileNameW    = comdlg32.NewProc("GetOpenFileNameW")
	pCoInitializeEx      = ole32.NewProc("CoInitializeEx")
	pCoTaskMemFree       = ole32.NewProc("CoTaskMemFree")
	pMessageBoxW         = user32.NewProc("MessageBoxW")
)

const createNoWindow = 0x08000000

// hidden prepara un comando sin ventana de consola.
// belowNormal: lo que se lanza en segundo plano no compite con lo que estás haciendo.
const belowNormal = 0x00004000

func hidden(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow | belowNormal}
	return cmd
}

func sysDir() string {
	d, err := windows.GetSystemDirectory()
	if err != nil {
		return `C:\Windows\System32`
	}
	return d
}

func psExe() string { return filepath.Join(sysDir(), `WindowsPowerShell\v1.0\powershell.exe`) }

// runPS ejecuta un script de PowerShell oculto y devuelve su salida en UTF-8.
func runPS(script string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	pre := "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
	cmd := hidden(exec.CommandContext(ctx, psExe(), psArgs(pre+script)...))
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return out.String(), errors.New("tardó demasiado y se ha cancelado")
	}
	if err != nil && out.Len() == 0 {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if msg == "" {
			msg = err.Error()
		}
		return "", errors.New(msg)
	}
	return out.String(), nil
}

// psArgs: el script va EN CLARO como argumento de -Command (se ve tal cual en el Administrador
// de tareas). Nada de -EncodedCommand ni -ExecutionPolicy Bypass: -Command no necesita
// saltarse la directiva, que solo afecta a archivos .ps1.
func psArgs(script string) []string {
	return []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script}
}

// runExe ejecuta un programa oculto y devuelve salida combinada.
func runExe(timeout time.Duration, name string, args ...string) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := hidden(exec.CommandContext(ctx, name, args...))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	code := 0
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() == context.DeadlineExceeded {
		return out.String(), -1, errors.New("tardó demasiado y se ha cancelado")
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return out.String(), code, nil
		}
		return out.String(), code, err
	}
	return out.String(), code, nil
}

// psq escapa un texto para meterlo entre comillas simples en PowerShell.
func psq(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func isAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(&windows.SECURITY_NT_AUTHORITY, 2, windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	ok, err := windows.Token(0).IsMember(sid)
	return err == nil && ok
}

func shellOpen(target, args string) {
	verb, _ := windows.UTF16PtrFromString("open")
	t, _ := windows.UTF16PtrFromString(target)
	var a *uint16
	if args != "" {
		a, _ = windows.UTF16PtrFromString(args)
	}
	pShellExecuteW.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(a)), 0, 1)
}

// openURL abre solo direcciones web o de Ajustes de Windows.
func openURL(u string) {
	l := strings.ToLower(u)
	if strings.HasPrefix(l, "https://") || strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "ms-settings:") || strings.HasPrefix(l, "windowsdefender:") {
		shellOpen(u, "")
	}
}

func reveal(p string) {
	if _, err := os.Stat(p); err != nil {
		p = filepath.Dir(p)
		shellOpen(p, "")
		return
	}
	hidden(exec.Command(filepath.Join(os.Getenv("WINDIR"), "explorer.exe"), "/select,", p)).Start()
}

func msgBox(title, text string) {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	pMessageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x40)
}

// ---------- diálogos (en su propio hilo con COM) ----------

type openFileName struct {
	lStructSize       uint32
	hwndOwner         uintptr
	hInstance         uintptr
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        uintptr
	dwReserved        uint32
	flagsEx           uint32
}

func onUIThreadless(f func() string) string {
	ch := make(chan string, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		pCoInitializeEx.Call(0, 0x2) // COINIT_APARTMENTTHREADED
		ch <- f()
	}()
	return <-ch
}

func pickFile(owner uintptr, title string) string {
	return onUIThreadless(func() string {
		buf := make([]uint16, 4096)
		filter := utf16.Encode([]rune("Todos los archivos\x00*.*\x00\x00"))
		t, _ := windows.UTF16PtrFromString(title)
		dl, _ := windows.UTF16PtrFromString(filepath.Join(desktopUserHome(), "Downloads"))
		ofn := openFileName{hwndOwner: owner, lpstrFilter: &filter[0], lpstrFile: &buf[0], nMaxFile: uint32(len(buf)), lpstrTitle: t, lpstrInitialDir: dl,
			flags: 0x00001000 | 0x00000800 | 0x00080000 | 0x02000000} // FILEMUSTEXIST|PATHMUSTEXIST|EXPLORER|DONTADDTORECENT
		ofn.lStructSize = uint32(unsafe.Sizeof(ofn))
		r, _, _ := pGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
		if r == 0 {
			return ""
		}
		return windows.UTF16ToString(buf)
	})
}

type browseInfo struct {
	hwndOwner      uintptr
	pidlRoot       uintptr
	pszDisplayName *uint16
	lpszTitle      *uint16
	ulFlags        uint32
	lpfn           uintptr
	lParam         uintptr
	iImage         int32
}

func pickFolder(owner uintptr, title string) string {
	return onUIThreadless(func() string {
		name := make([]uint16, 260)
		t, _ := windows.UTF16PtrFromString(title)
		bi := browseInfo{hwndOwner: owner, pszDisplayName: &name[0], lpszTitle: t, ulFlags: 0x1 | 0x40} // RETURNONLYFSDIRS|NEWDIALOGSTYLE
		pidl, _, _ := pSHBrowseForFolderW.Call(uintptr(unsafe.Pointer(&bi)))
		if pidl == 0 {
			return ""
		}
		defer pCoTaskMemFree.Call(pidl)
		buf := make([]uint16, 1024)
		pSHGetPathFromIDList.Call(pidl, uintptr(unsafe.Pointer(&buf[0])))
		return windows.UTF16ToString(buf)
	})
}

func diskFree(root string) (free, total uint64) {
	p, _ := windows.UTF16PtrFromString(root)
	var fa, tot, tf uint64
	if windows.GetDiskFreeSpaceEx(p, &fa, &tot, &tf) == nil {
		return tf, tot
	}
	return 0, 0
}

func computerName() string {
	n, _ := os.Hostname()
	if n == "" {
		n = os.Getenv("COMPUTERNAME")
	}
	return n
}

func errf(format string, a ...any) error { return fmt.Errorf(format, a...) }

var (
	wtsapi32                     = windows.NewLazySystemDLL("wtsapi32.dll")
	pWTSQuerySessionInformationW = wtsapi32.NewProc("WTSQuerySessionInformationW")
	pWTSFreeMemory               = wtsapi32.NewProc("WTSFreeMemory")
	pWTSGetActiveConsoleSession  = kernel32.NewProc("WTSGetActiveConsoleSessionId")
)

// desktopUserHome: carpeta del usuario que está delante de la pantalla (puede no ser la cuenta
// con la que corre el programa si se elevó con la .adm).
func desktopUserHome() string {
	home, _ := os.UserHomeDir()
	sid, _, _ := pWTSGetActiveConsoleSession.Call()
	if sid == 0xFFFFFFFF {
		return home
	}
	var buf *uint16
	var n uint32
	r, _, _ := pWTSQuerySessionInformationW.Call(0, sid, 5 /* WTSUserName */, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || buf == nil {
		return home
	}
	user := windows.UTF16PtrToString(buf)
	pWTSFreeMemory.Call(uintptr(unsafe.Pointer(buf)))
	if user == "" {
		return home
	}
	base := filepath.Dir(home)
	// perfiles de dominio pueden llamarse usuario.DOMINIO
	if m, _ := filepath.Glob(filepath.Join(base, user+"*")); len(m) > 0 {
		for _, c := range m {
			if strings.EqualFold(filepath.Base(c), user) {
				return c
			}
		}
		return m[0]
	}
	return home
}

// runExeStream ejecuta un programa oculto enseñando en directo su salida en la consola de la
// ventana de progreso, y convierte las barras de winget en porcentaje real.
func runExeStream(e *Engine, timeout time.Duration, name string, args ...string) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := hidden(exec.CommandContext(ctx, name, args...))
	var all strings.Builder
	last, lastPct := "", -10
	ls := &LineSplitter{Emit: func(line string, cr bool) {
		all.WriteString(line)
		all.WriteByte('\n')
		if pct, txt, ok := ParseProgress(line); ok {
			if txt == "" {
				txt = ternary(pct >= 100, "Completado", "Trabajando…")
			}
			e.SetSub(txt, pct)
			if pct >= lastPct+25 || (pct == 100 && lastPct != 100) {
				lastPct = pct
				e.Out(fmt.Sprintf("  %s · %d %%", txt, pct))
			}
			return
		}
		if IsNoise(line) || strings.TrimSpace(line) == "BSOK" || strings.TrimSpace(line) == "REBOOT" {
			return
		}
		t := strings.TrimRight(line, " ")
		if t == last {
			return
		}
		last = t
		e.Out(t)
		if st := wingetStage(t); st != "" {
			e.SetSub(st, -1)
			if st == "Instalando" {
				lastPct = -10
			}
		}
	}}
	cmd.Stdout, cmd.Stderr = ls, ls
	err := cmd.Run()
	ls.Close()
	code := 0
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() == context.DeadlineExceeded {
		return all.String(), -1, errors.New("tardó demasiado y se ha cancelado")
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return all.String(), code, nil
		}
		return all.String(), code, err
	}
	return all.String(), code, nil
}

// runPSStream: como runPS, pero enseñando lo que se ejecuta y lo que responde.
func runPSStream(e *Engine, script string, timeout time.Duration) (string, error) {
	for _, ln := range strings.Split(script, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || ln == "'BSOK'" || strings.HasPrefix(ln, "#") {
			continue
		}
		if len(ln) > 180 {
			ln = ln[:180] + "…"
		}
		e.Cmd("PS %s", ln)
	}
	pre := "$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
	out, code, err := runExeStream(e, timeout, psExe(), psArgs(pre+script)...)
	if err != nil {
		return out, err
	}
	if code != 0 && !strings.Contains(out, "BSOK") {
		return out, fmt.Errorf("PowerShell terminó con el código %d", code)
	}
	return out, nil
}

func syscallUTF16(s string) (*uint16, error) { return windows.UTF16PtrFromString(s) }
func utf16ToString(b []uint16) string        { return windows.UTF16ToString(b) }
