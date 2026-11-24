package webviewloader

// BlueShieldAA: WebView2Loader.dll (firmada por Microsoft) se carga SOLO desde disco, desde la
// carpeta del programa y con ruta completa. Se ha quitado la copia incrustada que se cargaba
// directamente en memoria: es una técnica que los antivirus asocian con malware.

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func loaderPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "WebView2Loader.dll"
	}
	return filepath.Join(filepath.Dir(exe), "WebView2Loader.dll")
}

var (
	nativeModule                                       = windows.NewLazyDLL(loaderPath())
	nativeCreate                                       = nativeModule.NewProc("CreateCoreWebView2EnvironmentWithOptions")
	nativeCompareBrowserVersions                       = nativeModule.NewProc("CompareBrowserVersions")
	nativeGetAvailableCoreWebView2BrowserVersionString = nativeModule.NewProc("GetAvailableCoreWebView2BrowserVersionString")
)

func load() error {
	if err := nativeModule.Load(); err != nil {
		return fmt.Errorf("no se encuentra WebView2Loader.dll junto al programa (%s): %w", loaderPath(), err)
	}
	return nil
}

// CompareBrowserVersions compara dos versiones: -1, 0 o 1.
func CompareBrowserVersions(v1 string, v2 string) (int, error) {
	_v1, err := windows.UTF16PtrFromString(v1)
	if err != nil {
		return 0, err
	}
	_v2, err := windows.UTF16PtrFromString(v2)
	if err != nil {
		return 0, err
	}
	if err := load(); err != nil {
		return 0, err
	}
	var result int
	_, _, err = nativeCompareBrowserVersions.Call(uintptr(unsafe.Pointer(_v1)), uintptr(unsafe.Pointer(_v2)), uintptr(unsafe.Pointer(&result)))
	if err != windows.ERROR_SUCCESS {
		return result, err
	}
	return result, nil
}

// GetInstalledVersion devuelve la versión instalada de WebView2 ("" si no hay).
func GetInstalledVersion() (string, error) {
	if err := load(); err != nil {
		return "", err
	}
	var result *uint16
	hr, _, _ := nativeGetAvailableCoreWebView2BrowserVersionString.Call(uintptr(unsafe.Pointer(nil)), uintptr(unsafe.Pointer(&result)))
	defer windows.CoTaskMemFree(unsafe.Pointer(result))
	if hr != uintptr(windows.S_OK) {
		if hr&0xFFFF == uintptr(windows.ERROR_FILE_NOT_FOUND) {
			return "", nil
		}
		return "", fmt.Errorf("GetAvailableCoreWebView2BrowserVersionString devolvió 0x%X", hr)
	}
	return windows.UTF16PtrToString(result), nil
}

// CreateCoreWebView2EnvironmentWithOptions llama a la función del cargador oficial.
func CreateCoreWebView2EnvironmentWithOptions(browserExecutableFolder, userDataFolder *uint16, environmentOptions uintptr, environmentCompletedHandle uintptr) (uintptr, error) {
	if err := load(); err != nil {
		return 0, err
	}
	res, _, _ := nativeCreate.Call(uintptr(unsafe.Pointer(browserExecutableFolder)), uintptr(unsafe.Pointer(userDataFolder)), environmentOptions, environmentCompletedHandle)
	return res, nil
}
