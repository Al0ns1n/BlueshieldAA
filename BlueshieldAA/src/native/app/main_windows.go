//go:build windows

package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

//go:embed web/index.html
var indexHTML string

var (
	pSetWindowLongPtrW = user32.NewProc("SetWindowLongPtrW")
	pCallWindowProcW   = user32.NewProc("CallWindowProcW")
	pSetWindowPos      = user32.NewProc("SetWindowPos")
	pIsZoomed          = user32.NewProc("IsZoomed")
	pShowWindow        = user32.NewProc("ShowWindow")
	pReleaseCapture    = user32.NewProc("ReleaseCapture")
	pSendMessageW      = user32.NewProc("SendMessageW")
	pPostMessageW      = user32.NewProc("PostMessageW")
	pGetSystemMetrics  = user32.NewProc("GetSystemMetrics")
	pFindWindowW       = user32.NewProc("FindWindowW")
	pSetForegroundWnd  = user32.NewProc("SetForegroundWindow")
	pGetDpiForWindow   = user32.NewProc("GetDpiForWindow")
	dwmapi             = windows.NewLazySystemDLL("dwmapi.dll")
	pDwmExtendFrame    = dwmapi.NewProc("DwmExtendFrameIntoClientArea")
)

const (
	wmClose         = 0x0010
	wmGetMinMaxInfo = 0x0024
	wmNCCalcSize    = 0x0083
	wmNCLButtonDown = 0x00A1
	wmSysCommand    = 0x0112
	scMinimize      = 0xF020
	htCaption       = 2
)

type App struct {
	St       *Store
	E        *Engine
	W        webview2.WebView
	hwnd     uintptr
	oldProc  uintptr
	force    bool
	portable bool
	lastFA   *FAResult
}

var app *App

func dataDir() (dir string, portable bool) {
	exe, _ := os.Executable()
	ed := filepath.Dir(exe)
	if _, err := os.Stat(filepath.Join(ed, "portable")); err == nil {
		d := filepath.Join(ed, "datos", "v4")
		if os.MkdirAll(d, 0o755) == nil {
			if f, err := os.CreateTemp(d, "w*"); err == nil {
				f.Close()
				os.Remove(f.Name())
				return d, true
			}
		}
		return filepath.Join(os.Getenv("LOCALAPPDATA"), AppName, "portable", "v4"), true
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	// subcarpeta "v4": los datos de la 3.x se quedan intactos por si hay que volver atrás
	return filepath.Join(pd, AppName, "v4"), false
}

func main() {
	runtime.LockOSThread()
	// Las tareas programadas de la 3.x (--guard, --agent, --watch, --nightly…) pueden seguir
	// lanzando este .exe: la 4.0 no las usa, así que sale sin hacer nada.
	// La 4.1 solo atiende --guardian (tarea del anti-ransomware), --liberar (desbloquear.cmd) y
	// --desinstalar (desinstalador).
	for _, a := range os.Args[1:] {
		switch a {
		case "--guardian":
			runGuardian()
			return
		case "--liberar", "--desinstalar":
			guardCLI(a)
			return
		}
		if strings.HasPrefix(a, "--") {
			return
		}
	}

	// Ya abierto: se trae al frente
	title, _ := windows.UTF16PtrFromString(AppName)
	class, _ := windows.UTF16PtrFromString("webview")
	if h, _, _ := pFindWindowW.Call(uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title))); h != 0 {
		pShowWindow.Call(h, 9)
		pSetForegroundWnd.Call(h)
		return
	}

	if exe, err := os.Executable(); err == nil {
		_ = LoadRules(filepath.Join(filepath.Dir(exe), "reglas-analisis.json"))
	}
	dir, portable := dataDir()
	_ = os.MkdirAll(dir, 0o755)
	if !portable && isAdmin() {
		lockDown(dir)
	}
	st := NewStore(dir)
	setupCrashLog(st)
	HostInfoPath = st.Path("equipo.json")
	e := NewEngine(st)
	registerScanners(e)
	registerActions(e)
	app = &App{St: st, E: e, portable: portable}

	// Menos consumo: el motor de la ventana no hace tareas de fondo que aquí no sirven
	// (descargar componentes, comprobaciones de red del navegador…) y el Go recoge memoria antes.
	if os.Getenv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS") == "" {
		os.Setenv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "--disable-background-networking --disable-component-update --disable-sync --disable-features=msSmartScreenProtection,msWebOOUI,msPdfOOUI,Translate --renderer-process-limit=1")
	}
	debug.SetMemoryLimit(160 << 20)
	wvData := filepath.Join(os.Getenv("LOCALAPPDATA"), AppName, "webview")
	if portable {
		wvData = filepath.Join(dir, "webview")
	}
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		DataPath:      wvData,
		AutoFocus:     true,
		WindowOptions: webview2.WindowOptions{Title: AppName, Width: 1320, Height: 860, IconId: 1, Center: true},
	})
	if w == nil {
		if exe, _ := os.Executable(); exe != "" {
			if _, err := os.Stat(filepath.Join(filepath.Dir(exe), "WebView2Loader.dll")); err != nil {
				msgBox(AppName, "Falta el archivo WebView2Loader.dll junto a BlueShieldAA.exe.\n\nVuelve a instalar BlueShieldAA o, en la versión portable, descomprime la carpeta completa.")
				return
			}
		}
		msgBox(AppName, "Falta Microsoft Edge WebView2 Runtime, que es lo que dibuja la ventana.\n\nSe abrirá la página de Microsoft para instalarlo (es gratuito). Después vuelve a abrir BlueShieldAA.")
		openURL("https://go.microsoft.com/fwlink/p/?LinkId=2124703")
		return
	}
	app.W = w
	app.hwnd = uintptr(w.Window())
	app.frameless()
	app.bind()
	html := strings.Replace(indexHTML, "'__MODE__'", "'app'", 1)
	w.SetHtml(html)
	e.Log("info", "BlueShieldAA %s abierto%s. Datos en %s", AppVersion, ternary(isAdmin(), " con permisos de administrador", " SIN permisos de administrador"), dir)
	go func() { time.Sleep(25 * time.Second); collector.ensureInfo() }() // ficha del equipo lista para Hardware y Diagnóstico
	w.Run()
	w.Destroy()
}

// ---------- ventana sin marco (la barra de título la dibuja la interfaz) ----------

type rect struct{ l, t, r, b int32 }

type minMaxInfo struct {
	reserved, maxSize, maxPos, minTrack, maxTrack struct{ x, y int32 }
}

func (a *App) frameless() {
	cb := syscall.NewCallback(func(h, msg, wp, lp uintptr) uintptr {
		switch msg {
		case wmNCCalcSize:
			if wp == 1 {
				if z, _, _ := pIsZoomed.Call(h); z != 0 {
					// maximizada: Windows la saca unos píxeles por cada lado
					fx, _, _ := pGetSystemMetrics.Call(32) // SM_CXSIZEFRAME
					fy, _, _ := pGetSystemMetrics.Call(33)
					pad, _, _ := pGetSystemMetrics.Call(92) // SM_CXPADDEDBORDER
					r := (*rect)(ptrOf(lp))
					r.l += int32(fx + pad)
					r.r -= int32(fx + pad)
					r.t += int32(fy + pad)
					r.b -= int32(fy + pad)
				}
				return 0
			}
		case wmClose:
			if !a.force && a.E.Busy() {
				a.W.Dispatch(func() { a.W.Eval("window.askClose && askClose()") })
				return 0
			}
		case wmGetMinMaxInfo:
			r, _, _ := pCallWindowProcW.Call(a.oldProc, h, msg, wp, lp)
			mm := (*minMaxInfo)(ptrOf(lp))
			dpi, _, _ := pGetDpiForWindow.Call(h)
			if dpi == 0 {
				dpi = 96
			}
			mm.minTrack.x = int32(980 * dpi / 96)
			mm.minTrack.y = int32(640 * dpi / 96)
			return r
		}
		r, _, _ := pCallWindowProcW.Call(a.oldProc, h, msg, wp, lp)
		return r
	})
	gwlpWndProc := -4
	a.oldProc, _, _ = pSetWindowLongPtrW.Call(a.hwnd, uintptr(gwlpWndProc), cb)
	m := [4]int32{0, 0, 1, 0} // sombra de Windows 10/11
	pDwmExtendFrame.Call(a.hwnd, uintptr(unsafe.Pointer(&m)))
	pSetWindowPos.Call(a.hwnd, 0, 0, 0, 0, 0, 0x0001|0x0002|0x0004|0x0020) // NOSIZE|NOMOVE|NOZORDER|FRAMECHANGED
}

var edgeHT = map[string]uintptr{"l": 10, "r": 11, "t": 12, "tl": 13, "tr": 14, "b": 15, "bl": 16, "br": 17}

func (a *App) drag(ht uintptr) {
	a.W.Dispatch(func() {
		pReleaseCapture.Call()
		pSendMessageW.Call(a.hwnd, wmNCLButtonDown, ht, 0)
	})
}

func (a *App) toggleMax() bool {
	z, _, _ := pIsZoomed.Call(a.hwnd)
	if z != 0 {
		pShowWindow.Call(a.hwnd, 9) // SW_RESTORE
		return false
	}
	pShowWindow.Call(a.hwnd, 3) // SW_MAXIMIZE
	return true
}

func (a *App) close(force bool) {
	a.force = force
	pPostMessageW.Call(a.hwnd, wmClose, 0, 0)
}

func init() {
	// la hora de los registros, en hora local aunque el proceso venga de un servicio
	time.Local = time.Now().Location()
}

// ptrOf convierte el puntero que Windows pasa en lParam (memoria que no gestiona Go).
func ptrOf(p uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&p)) }

// lockDown: la carpeta de datos solo la pueden cambiar SYSTEM y Administradores (los usuarios
// normales solo leer). Así nadie sin permisos puede manipular la cuarentena o la foto de cambios.
func lockDown(dir string) {
	icacls := filepath.Join(sysDir(), "icacls.exe")
	_, _, _ = runExe(30*time.Second, icacls, dir, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/grant:r", "*S-1-5-32-545:(OI)(CI)RX", "/Q")
}

// ---------- registro de fallos ----------

// setupCrashLog: si el programa se cae (también por errores graves de Go que no se pueden
// capturar), Windows no enseña nada; así queda escrito en fallos.txt con el detalle.
func setupCrashLog(st *Store) {
	f, err := os.OpenFile(st.Path("fallos.txt"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		fmt.Fprintf(f, "\r\n=== BlueShieldAA %s abierto el %s ===\r\n", AppVersion, time.Now().Format("2006-01-02 15:04:05"))
		_ = debug.SetCrashOutput(f, debug.CrashOptions{})
	}
	webview2.OnPanic = func(method string, r any, stack []byte) {
		logPanic(st, "función "+method, r, stack)
		if app != nil {
			app.E.Log("err", "✖ Fallo interno en %s: %v (anotado en fallos.txt; el programa sigue funcionando)", method, r)
		}
	}
	panicHook = func(where string, r any, stack []byte) { logPanic(st, where, r, stack) }
}

func logPanic(st *Store, where string, r any, stack []byte) {
	f, err := os.OpenFile(st.Path("fallos.txt"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "\r\n--- %s · fallo capturado en %s: %v\r\n%s\r\n", time.Now().Format("2006-01-02 15:04:05"), where, r, stack)
}

// lastCrash: si la última vez el programa se cerró por un fallo grave, devuelve un resumen.
func (a *App) lastCrash() string {
	b, err := os.ReadFile(a.St.Path("fallos.txt"))
	if err != nil {
		return ""
	}
	s := string(b)
	// fallos.txt tiene un bloque por cada vez que se abre: se mira el penúltimo (la sesión anterior)
	parts := strings.Split(s, "=== BlueShieldAA ")
	if len(parts) < 3 {
		return ""
	}
	prev := parts[len(parts)-2]
	for _, mark := range []string{"fatal error:", "panic:", "Exception 0x", "unexpected fault address"} {
		if i := strings.Index(prev, mark); i >= 0 {
			line := prev[i:]
			if j := strings.IndexAny(line, "\r\n"); j > 0 {
				line = line[:j]
			}
			return line
		}
	}
	return ""
}
