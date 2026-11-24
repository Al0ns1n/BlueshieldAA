//go:build windows

package main

import (
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func devKey(guid string, pid uint32) *windows.DEVPROPKEY {
	g, _ := windows.GUIDFromString(guid)
	return &windows.DEVPROPKEY{FmtID: windows.DEVPROPGUID(g), PID: windows.DEVPROPID(pid)}
}

var (
	keyBusDesc  = devKey("{540b947e-8b40-45bc-a8a2-6a0b894cbda2}", 4)
	keyFwVer    = devKey("{540b947e-8b40-45bc-a8a2-6a0b894cbda2}", 18)
	keyDrvVer   = devKey("{a8b865dd-2e3d-4094-ad97-e593a70c75d6}", 3)
	keyDrvProv  = devKey("{a8b865dd-2e3d-4094-ad97-e593a70c75d6}", 9)
	devCache    []PnPDev
	devCacheAt  time.Time
	devCacheMux sync.Mutex
)

// PnPDevices: lista de dispositivos presentes (como el Administrador de dispositivos), sin PowerShell.
func PnPDevices() []PnPDev {
	devCacheMux.Lock()
	defer devCacheMux.Unlock()
	if time.Since(devCacheAt) < 3*time.Second && devCache != nil {
		return devCache
	}
	set, err := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_PRESENT|windows.DIGCF_ALLCLASSES, 0, "")
	if err != nil {
		return nil
	}
	defer set.Close()
	str := func(d *windows.DevInfoData, p windows.SPDRP) string {
		v, err := set.DeviceRegistryProperty(d, p)
		if err != nil {
			return ""
		}
		switch x := v.(type) {
		case string:
			return strings.TrimSpace(x)
		case []string:
			if len(x) > 0 {
				return x[0]
			}
		}
		return ""
	}
	prop := func(d *windows.DevInfoData, k *windows.DEVPROPKEY) string {
		v, err := windows.SetupDiGetDeviceProperty(set, d, k)
		if err != nil {
			return ""
		}
		s, _ := v.(string)
		return strings.TrimSpace(s)
	}
	var out []PnPDev
	for i := 0; ; i++ {
		d, err := set.EnumDeviceInfo(i)
		if err != nil {
			if err == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}
		id, _ := set.DeviceInstanceID(d)
		p := PnPDev{Instance: id, Class: str(d, windows.SPDRP_CLASS), Name: str(d, windows.SPDRP_FRIENDLYNAME), Mfg: str(d, windows.SPDRP_MFG),
			Enum: str(d, windows.SPDRP_ENUMERATOR_NAME), Container: str(d, windows.SPDRP_BASE_CONTAINERID), Location: str(d, windows.SPDRP_LOCATION_INFORMATION)}
		if p.Name == "" {
			p.Name = str(d, windows.SPDRP_DEVICEDESC)
		}
		p.BusDesc = prop(d, keyBusDesc)
		p.DrvVer = prop(d, keyDrvVer)
		p.DrvProv = prop(d, keyDrvProv)
		p.FwVer = prop(d, keyFwVer)
		var status, problem uint32
		if windows.CM_Get_DevNode_Status(&status, &problem, d.DevInst, 0) == nil && status&0x400 != 0 { // DN_HAS_PROBLEM
			p.Problem = problem
			p.Disabled = problem == 22
		}
		out = append(out, p)
	}
	devCache, devCacheAt = out, time.Now()
	return out
}

// Devices: lo que pide la página de Hardware → Conectados.
func Devices() map[string]any {
	ext, in := GroupDevices(PnPDevices())
	if ext == nil {
		ext = []DevGroup{}
	}
	if in == nil {
		in = []DevGroup{}
	}
	return map[string]any{"external": ext, "internal": in, "at": time.Now().UnixMilli()}
}

// HardwareInfo: ficha del equipo (procesador, memoria, gráfica, discos…) + placa, BIOS y Windows.
func HardwareInfo() map[string]any {
	info := HostInfo()
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE); err == nil {
		g := func(n string) string { v, _, _ := k.GetStringValue(n); return strings.TrimSpace(v) }
		info["boardMaker"], info["boardModel"] = g("BaseBoardManufacturer"), g("BaseBoardProduct")
		info["sysMaker"], info["sysModel"] = g("SystemManufacturer"), g("SystemProductName")
		info["bios"], info["biosDate"], info["biosVendor"] = g("BIOSVersion"), g("BIOSReleaseDate"), g("BIOSVendor")
		k.Close()
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		g := func(n string) string { v, _, _ := k.GetStringValue(n); return strings.TrimSpace(v) }
		build := g("CurrentBuild")
		name := g("ProductName")
		if b := atoiSafe(build); b >= 22000 {
			name = strings.Replace(name, "Windows 10", "Windows 11", 1) // Windows 11 sigue diciendo «Windows 10» en el registro
		}
		ubr, _, _ := k.GetIntegerValue("UBR")
		info["osName"], info["osVersion"], info["osBuild"] = name, g("DisplayVersion"), build+"."+itoa(int(ubr))
		k.Close()
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringValue("ProcessorNameString"); err == nil && info["cpu"] == nil {
			info["cpu"] = strings.TrimSpace(v)
		}
		k.Close()
	}
	info["computer"] = computerName()
	info["logical"] = numCPU()
	var ms memStatus
	ms.len = uint32(unsafe.Sizeof(ms))
	pGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	info["memTotal"] = ms.total
	info["user"] = os.Getenv("USERNAME")
	return info
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
