package main

// Aplicaciones instaladas: lo que sale en «Aplicaciones instaladas» de Windows, leído del
// registro (sin PowerShell), más las apps de Microsoft Store. Parte portable.

import (
	"sort"
	"strings"
	"time"
)

type InstalledApp struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Publisher string `json:"publisher"`
	Installed string `json:"installed"` // AAAA-MM-DD
	Size      int64  `json:"size"`
	Location  string `json:"location"`
	Uninstall string `json:"-"`
	Kind      string `json:"kind"`  // "Programa" | "Componente" | "Tienda"
	Scope     string `json:"scope"` // "Todos los usuarios" | "Solo este usuario"
	Arch      string `json:"arch"`  // "64 bits" | "32 bits"
	Update    string `json:"update,omitempty"`
	CanRemove bool   `json:"canRemove"`
	Icon      string `json:"-"`
}

// AppKind separa los programas de verdad de los componentes que instalan otros programas.
func AppKind(name, publisher string) string {
	l := strings.ToLower(name)
	if hasAny(l, "redistributable", "runtime", "visual c++", ".net", "directx", "webview2", "sdk", "driver", "controlador", "chipset", "update health", "bonjour", "vcredist",
		"windows software development", "kits", "microsoft edge update", "language pack", "paquete de idioma", "help", "telemetry", "click-to-run", "vs_", "targeting pack", "manifest", "msi development", "application verifier", "shared", "prerequisites") {
		return "Componente"
	}
	return "Programa"
}

// ParseInstallDate: "20241105" → "2024-11-05".
func ParseInstallDate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 8 {
		if t, err := time.Parse("20060102", s); err == nil {
			return t.Format("2006-01-02")
		}
	}
	return ""
}

// MergeApps quita duplicados (mismo programa en 32 y 64 bits o por usuario y para todos)
// y marca los que tienen actualización pendiente (nombre → versión nueva).
func MergeApps(l []InstalledApp, updates map[string]string) []InstalledApp {
	seen := map[string]int{}
	var out []InstalledApp
	for _, a := range l {
		a.Name = strings.TrimSpace(a.Name)
		if a.Name == "" {
			continue
		}
		if a.Kind == "" {
			a.Kind = AppKind(a.Name, a.Publisher)
		}
		k := strings.ToLower(a.Name) + "|" + a.Version
		if i, ok := seen[k]; ok {
			if out[i].Size == 0 {
				out[i].Size = a.Size
			}
			if out[i].Location == "" {
				out[i].Location = a.Location
			}
			continue
		}
		if v, ok := updates[NameKey(a.Name)]; ok && v != "" && v != a.Version {
			a.Update = v
		}
		seen[k] = len(out)
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// StoreAppName: "Microsoft.WindowsCalculator_11.2405.2.0_x64__8wekyb3d8bbwe" → nombre, versión, editor.
func StoreAppName(full string) (name, version, publisherID string) {
	f := strings.Split(full, "_")
	if len(f) < 5 {
		return full, "", ""
	}
	return f[0], f[1], f[len(f)-1]
}

// StoreHidden: paquetes de la Tienda que no son apps para el usuario (marcos, extensiones…).
func StoreHidden(id string) bool {
	l := strings.ToLower(id)
	return hasAny(l, "microsoft.vclibs", "microsoft.net.", "microsoft.ui.xaml", "microsoft.services.store.engagement", "microsoft.advertising", "windowsappruntime", "microsoft.directx",
		"extension", "microsoft.windows.cloudexperiencehost", "microsoft.aad.brokerplugin", "microsoft.accountscontrol", "microsoft.asynctextservice", "microsoft.bioenrollment", "microsoft.creddialoghost",
		"microsoft.ecapp", "microsoft.lockapp", "microsoft.windows.", "windows.", "microsoftwindows.", "microsoft.win32webviewhost", "ncsiuwpapp", "microsoft.languageexperiencepack", "inputapp", "microsoft.desktopappinstaller",
		"microsoft.storepurchaseapp", "microsoft.webpimageextension", "microsoft.heifimageextension", "microsoft.vp9videoextensions", "microsoft.webmediaextensions", "microsoft.hevcvideoextension", "microsoft.rawimageextension",
		"1527c705-839a-4832-9118-54d4bd6a0c89", "c5e2524a-ea46-4f67-841f-6a9465d9d515", "e2a4f912-2574-4a75-9bb0-0d023378592b", "f46d4000-fd22-4db4-ac8e-4e1ddde828fe", "microsoft.xboxgamecallableui", "microsoft.xboxidentityprovider", "microsoft.gamingservices")
}
