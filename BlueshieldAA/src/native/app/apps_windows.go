//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	shlwapi            = windows.NewLazySystemDLL("shlwapi.dll")
	pSHLoadIndirectStr = shlwapi.NewProc("SHLoadIndirectString")
)

// desktopUserSID: SID del usuario que está delante de la pantalla (para leer sus programas
// aunque BlueShieldAA se haya abierto con la cuenta .adm).
func desktopUserSID() string {
	home := strings.ToLower(desktopUserHome())
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return ""
	}
	defer k.Close()
	sids, _ := k.ReadSubKeyNames(0)
	for _, s := range sids {
		sk, err := registry.OpenKey(k, s, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		p, _, _ := sk.GetStringValue("ProfileImagePath")
		sk.Close()
		if strings.EqualFold(os.ExpandEnv(p), home) || strings.ToLower(p) == home {
			return s
		}
	}
	return ""
}

func indirect(s string) string {
	if !strings.HasPrefix(s, "@") {
		return s
	}
	in, _ := windows.UTF16PtrFromString(s)
	buf := make([]uint16, 512)
	if r, _, _ := pSHLoadIndirectStr.Call(uintptr(unsafe.Pointer(in)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0); r != 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}

func readUninstall(root registry.Key, path, scope, arch string, out *[]InstalledApp) {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	defer k.Close()
	subs, _ := k.ReadSubKeyNames(0)
	for _, sub := range subs {
		sk, err := registry.OpenKey(k, sub, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		get := func(n string) string { v, _, _ := sk.GetStringValue(n); return strings.TrimSpace(v) }
		num := func(n string) uint64 { v, _, _ := sk.GetIntegerValue(n); return v }
		name := get("DisplayName")
		sysComp := num("SystemComponent") == 1
		parent := get("ParentKeyName")
		rel := strings.ToLower(get("ReleaseType"))
		if name == "" || sysComp || parent != "" || rel == "update" || rel == "hotfix" || rel == "security update" || strings.HasPrefix(sub, "KB") {
			sk.Close()
			continue
		}
		un := get("QuietUninstallString")
		if u := get("UninstallString"); u != "" {
			un = u // el normal: así el usuario ve el asistente y puede cancelar
		}
		a := InstalledApp{ID: scope[:1] + arch[:2] + ":" + sub, Name: name, Version: get("DisplayVersion"), Publisher: get("Publisher"), Installed: ParseInstallDate(get("InstallDate")),
			Size: int64(num("EstimatedSize")) * 1024, Location: get("InstallLocation"), Uninstall: un, Scope: scope, Arch: arch, CanRemove: un != "" && num("NoRemove") != 1, Icon: get("DisplayIcon")}
		sk.Close()
		*out = append(*out, a)
	}
}

func storeApps(sid string, out *[]InstalledApp) {
	if sid == "" {
		return
	}
	k, err := registry.OpenKey(registry.USERS, sid+`\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	defer k.Close()
	subs, _ := k.ReadSubKeyNames(0)
	for _, full := range subs {
		if StoreHidden(full) || strings.Contains(full, "_neutral_~_") || strings.Contains(full, "_neutral_split") {
			continue
		}
		sk, err := registry.OpenKey(k, full, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		dn, _, _ := sk.GetStringValue("DisplayName")
		root, _, _ := sk.GetStringValue("PackageRootFolder")
		sk.Close()
		id, ver, _ := StoreAppName(full)
		name := indirect(dn)
		if name == "" || strings.HasPrefix(name, "ms-resource") || strings.HasPrefix(name, "@{") {
			continue
		}
		pub := id
		if i := strings.Index(id, "."); i > 0 {
			pub = id[:i]
		}
		*out = append(*out, InstalledApp{ID: "store:" + full, Name: name, Version: ver, Publisher: pub, Location: root, Kind: "Tienda", Scope: "Solo este usuario", Arch: "Tienda", CanRemove: true})
	}
}

var appsCache struct {
	sync.Mutex
	at   time.Time
	list []InstalledApp
}

// InstalledApps: todo lo instalado (programas para todos, para el usuario y apps de la Tienda).
func InstalledApps(e *Engine) []InstalledApp {
	var l []InstalledApp
	readUninstall(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "Todos los usuarios", "64 bits", &l)
	readUninstall(registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "Todos los usuarios", "32 bits", &l)
	sid := desktopUserSID()
	if sid != "" {
		readUninstall(registry.USERS, sid+`\Software\Microsoft\Windows\CurrentVersion\Uninstall`, "Solo este usuario", "64 bits", &l)
	} else {
		readUninstall(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall`, "Solo este usuario", "64 bits", &l)
	}
	storeApps(sid, &l)
	upd := map[string]string{}
	for _, it := range e.Items() {
		if it.Category == "Programas" && (it.Status == "Actualizar" || it.Status == "Vulnerable") {
			upd[NameKey(it.Name)] = it.Available
		}
	}
	out := MergeApps(l, upd)
	// tamaño de los que no lo dicen: se mide la carpeta (solo si es razonable y en caché)
	appsCache.Lock()
	appsCache.list = out
	appsCache.at = time.Now()
	appsCache.Unlock()
	return out
}

func appByID(id string) *InstalledApp {
	appsCache.Lock()
	defer appsCache.Unlock()
	for i := range appsCache.list {
		if appsCache.list[i].ID == id {
			a := appsCache.list[i]
			return &a
		}
	}
	return nil
}

// AppUninstall abre el desinstalador del programa (el usuario ve su asistente y puede cancelar).
func AppUninstall(e *Engine, id string) string {
	a := appByID(id)
	if a == nil {
		return "No se encuentra el programa: vuelve a cargar la lista."
	}
	if a.Kind == "Tienda" {
		shellOpen("ms-settings:appsfeatures", "")
		return "Las apps de Microsoft Store se quitan desde Configuración → Aplicaciones (se ha abierto). Busca «" + a.Name + "»."
	}
	if !a.CanRemove || a.Uninstall == "" {
		return "Este programa no se puede desinstalar desde aquí."
	}
	exe := ServiceExe(a.Uninstall, os.Getenv("SystemRoot"))
	if !strings.ContainsAny(exe, `\/`) {
		exe = filepath.Join(sysDir(), exe)
	}
	cmd := exec.Command(exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: a.Uninstall}
	e.Cmd("%s", a.Uninstall)
	if err := cmd.Start(); err != nil {
		return "No se pudo abrir el desinstalador: " + err.Error()
	}
	go cmd.Wait()
	e.Log("info", "Abierto el desinstalador de %s", a.Name)
	return ""
}

func AppReveal(id string) string {
	a := appByID(id)
	if a == nil {
		return "No se encuentra el programa."
	}
	p := a.Location
	if p == "" && a.Icon != "" {
		p = filepath.Dir(strings.Trim(strings.Split(a.Icon, ",")[0], `"`))
	}
	if p == "" {
		return "Este programa no indica en qué carpeta está."
	}
	shellOpen(p, "")
	return ""
}
