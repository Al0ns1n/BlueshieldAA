//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"
)

var (
	pGetLogicalDrives = kernel32.NewProc("GetLogicalDrives")
	pGetDriveTypeW    = kernel32.NewProc("GetDriveTypeW")
	pGetVolumeInfoW   = kernel32.NewProc("GetVolumeInformationW")
)

type DriveInfo struct {
	Root  string `json:"root"`
	Label string `json:"label"`
	Total uint64 `json:"total"`
	Free  uint64 `json:"free"`
	Sys   bool   `json:"sys"`
}

func Drives() []DriveInfo {
	mask, _, _ := pGetLogicalDrives.Call()
	sys := strings.ToUpper(os.Getenv("SystemDrive"))
	out := []DriveInfo{}
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		p, _ := syscallUTF16(root)
		if t, _, _ := pGetDriveTypeW.Call(uintptr(unsafe.Pointer(p))); t != 3 { // solo discos fijos
			continue
		}
		free, total := diskFree(root)
		if total == 0 {
			continue
		}
		name := make([]uint16, 261)
		pGetVolumeInfoW.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&name[0])), 261, 0, 0, 0, 0, 0)
		out = append(out, DriveInfo{Root: root, Label: utf16ToString(name), Total: total, Free: free, Sys: strings.HasPrefix(root, sys)})
	}
	return out
}

// ---------- escaneo ----------

var diskScan = &DiskScan{}

func DiskStart(root string) string {
	if diskScan.Progress().State == "escaneando" {
		return "Ya se está analizando una unidad."
	}
	if len(root) < 2 || root[1] != ':' {
		return "Unidad no válida."
	}
	root = strings.ToUpper(root[:2]) + `\`
	free, total := diskFree(root)
	diskScan.mu.Lock()
	diskScan.Total, diskScan.Free = total, free
	diskScan.mu.Unlock()
	go diskScan.Scan(root)
	return ""
}

// ---------- borrado (en segundo plano, con progreso) ----------

type DelJob struct {
	Running bool         `json:"running"`
	Cur     string       `json:"cur"`
	Done    int          `json:"done"`
	Total   int          `json:"total"`
	Res     DeleteResult `json:"res"`
	Notes   []string     `json:"notes"`
	Binned  int64        `json:"binned"` // enviado a la papelera (se libera al vaciarla)
}

var delMu sync.Mutex
var delJob DelJob

func DelStatus() DelJob {
	delMu.Lock()
	defer delMu.Unlock()
	j := delJob
	j.Notes = append([]string{}, delJob.Notes...)
	return j
}

func DiskDelete(e *Engine, paths []string, toBin bool) string {
	delMu.Lock()
	if delJob.Running {
		delMu.Unlock()
		return "Ya se está borrando algo; espera a que termine."
	}
	delJob = DelJob{Running: true, Total: len(paths), Res: DeleteResult{Skipped: []string{}, Errors: []string{}}}
	delMu.Unlock()
	go func() {
		e.Log("title", "━━ Liberando espacio: %d elemento(s) ━━", len(paths))
		for i, p := range paths {
			delMu.Lock()
			delJob.Cur, delJob.Done = p, i
			delMu.Unlock()
			fi, err := os.Lstat(p)
			if err != nil {
				addNote(filepath.Base(p) + ": ya no existe.")
				continue
			}
			isDir := fi.IsDir()
			if ok, why := CanDelete(p, isDir); !ok {
				delMu.Lock()
				delJob.Res.Skipped = append(delJob.Res.Skipped, filepath.Base(p)+": "+why)
				delMu.Unlock()
				continue
			}
			c := ClassifyPath(p, isDir, fi.Size(), fi.ModTime())
			r := DeleteResult{}
			switch {
			case isDir && c.Inside:
				e.Cmd("Vaciar %s", p)
				deleteInside(p, &r)
				diskScan.Rescan(p)
			case c.Level == LvlBorrar || !toBin:
				before := fi.Size()
				if isDir {
					before = dirSize(p)
				}
				e.Cmd("Borrar %s", p)
				if err := os.RemoveAll(p); err != nil {
					after := int64(0)
					if _, e2 := os.Stat(p); e2 == nil {
						if isDir {
							after = dirSize(p)
						} else {
							after = before
						}
					}
					r.Freed = before - after
					r.Failed++
					r.Errors = append(r.Errors, filepath.Base(p)+": algunos archivos están en uso")
				} else {
					r.Freed, r.Deleted = before, 1
				}
				diskScan.Rescan(p)
			default:
				before := fi.Size()
				if isDir {
					before = dirSize(p)
				}
				e.Cmd("Enviar a la papelera %s", p)
				if err := toRecycleBin(p, isDir); err != nil {
					r.Failed++
					r.Errors = append(r.Errors, filepath.Base(p)+": "+err.Error())
				} else {
					r.Deleted = 1
					delMu.Lock()
					delJob.Binned += before
					delMu.Unlock()
					diskScan.Rescan(p)
				}
			}
			e.Out(fmt.Sprintf("%s: liberados %s%s", filepath.Base(p), fmtBytes(r.Freed), ternary(r.Failed > 0, fmt.Sprintf(" (%d en uso, se quedan)", r.Failed), "")))
			delMu.Lock()
			delJob.Res.Freed += r.Freed
			delJob.Res.Deleted += r.Deleted
			delJob.Res.Failed += r.Failed
			delJob.Res.Errors = append(delJob.Res.Errors, r.Errors...)
			delMu.Unlock()
		}
		delMu.Lock()
		delJob.Running, delJob.Done, delJob.Cur = false, len(paths), ""
		res := delJob.Res
		binned := delJob.Binned
		delMu.Unlock()
		e.Log("ok", "✔ Liberados %s%s%s.", fmtBytes(res.Freed), ternary(binned > 0, " y "+fmtBytes(binned)+" enviados a la papelera", ""), ternary(res.Failed > 0, fmt.Sprintf(" (%d archivo(s) en uso no se han podido borrar)", res.Failed), ""))
		// Limpieza rápida, Inicio y la barra lateral se ponen al día con lo que queda de verdad
		e.RefreshCats("Limpieza")
	}()
	return ""
}

func addNote(s string) {
	delMu.Lock()
	delJob.Notes = append(delJob.Notes, s)
	delMu.Unlock()
}

// toRecycleBin manda a la papelera (se puede recuperar).
func toRecycleBin(p string, isDir bool) error {
	fn := "DeleteFile"
	if isDir {
		fn = "DeleteDirectory"
	}
	out, err := runPS(`Add-Type -AssemblyName Microsoft.VisualBasic; [Microsoft.VisualBasic.FileIO.FileSystem]::`+fn+`(`+psq(p)+`, 'OnlyErrorDialogs', 'SendToRecycleBin'); 'BSOK'`, 30*time.Minute)
	if err != nil {
		return err
	}
	if !strings.Contains(out, "BSOK") {
		return fmt.Errorf("%s", firstLine(out))
	}
	return nil
}

// ---------- acciones oficiales de Windows ----------

func DiskAction(e *Engine, a string) string {
	switch a {
	case "hiber":
		before := int64(0)
		if fi, err := os.Stat(os.Getenv("SystemDrive") + `\hiberfil.sys`); err == nil {
			before = fi.Size()
		}
		e.Cmd("powercfg /hibernate off")
		out, code, err := runExe(time.Minute, filepath.Join(sysDir(), "powercfg.exe"), "/hibernate", "off")
		if err != nil || code != 0 {
			return "No se pudo desactivar la hibernación: " + firstLine(out)
		}
		diskScan.ForgetPath(os.Getenv("SystemDrive")+`\hiberfil.sys`, before, true)
		return "Hibernación desactivada: liberados " + fmtBytes(before) + ". Se puede volver a activar con «powercfg /hibernate on»."
	case "dism":
		go func() {
			e.Log("title", "━━ Limpieza de componentes de Windows (DISM) ━━")
			e.Cmd("DISM /Online /Cleanup-Image /StartComponentCleanup")
			out, code, err := runExeStream(e, 2*time.Hour, filepath.Join(sysDir(), "Dism.exe"), "/Online", "/Cleanup-Image", "/StartComponentCleanup")
			if err != nil || code != 0 {
				e.Log("err", "✖ DISM terminó con error: %s", firstLine(out))
				return
			}
			e.Log("ok", "✔ Componentes de Windows limpiados. Vuelve a analizar la unidad para ver el espacio liberado.")
		}()
		return "Limpieza de componentes de Windows en marcha (puede tardar entre 5 y 30 minutos). Lo verás en el Registro."
	case "storage":
		openURL("ms-settings:storagepolicies")
		return "Se ha abierto Configuración → Sistema → Almacenamiento. En «Archivos temporales» marca «Instalación anterior de Windows»."
	}
	return "Acción desconocida."
}

// ---------- limpieza rápida (la de la lista de Inicio): todos los usuarios y medida real ----------

func junkTargets(id string) []string {
	sys := os.Getenv("SystemDrive")
	users, _ := filepath.Glob(sys + `\Users\*`)
	var per = func(sub string) []string {
		var l []string
		for _, u := range users {
			b := strings.ToLower(filepath.Base(u))
			if b == "public" || b == "default" || b == "default user" || b == "all users" {
				continue
			}
			l = append(l, filepath.Join(u, sub))
		}
		return l
	}
	switch id {
	case "usertemp":
		return per(`AppData\Local\Temp`)
	case "wintemp":
		return []string{os.Getenv("WINDIR") + `\Temp`}
	case "wudl":
		return []string{os.Getenv("WINDIR") + `\SoftwareDistribution\Download`}
	case "recycle":
		var l []string
		for _, d := range Drives() {
			l = append(l, d.Root+`$Recycle.Bin`)
		}
		return l
	case "crash":
		return append([]string{os.Getenv("ProgramData") + `\Microsoft\Windows\WER`, os.Getenv("WINDIR") + `\Minidump`}, per(`AppData\Local\CrashDumps`)...)
	case "thumbs":
		return per(`AppData\Local\Microsoft\Windows\Explorer`)
	case "delivery":
		return []string{os.Getenv("WINDIR") + `\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache`}
	case "edgecache":
		return append(per(`AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data`), per(`AppData\Local\Microsoft\Edge\User Data\Default\Code Cache`)...)
	case "chromecache":
		return append(per(`AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data`), per(`AppData\Local\Google\Chrome\User Data\Default\Code Cache`)...)
	case "bravecache":
		return append(per(`AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Cache\Cache_Data`), per(`AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Code Cache`)...)
	case "ffcache":
		var l []string
		for _, b := range per(`AppData\Local\Mozilla\Firefox\Profiles`) {
			m, _ := filepath.Glob(filepath.Join(b, "*", "cache2"))
			l = append(l, m...)
		}
		return l
	}
	return nil
}

func cleanJunk(e *Engine, it *Item) (string, error) {
	targets := junkTargets(it.Arg)
	if len(targets) == 0 {
		return "", fmt.Errorf("no se sabe limpiar esto")
	}
	res := &DeleteResult{}
	for _, t := range targets {
		if _, err := os.Stat(t); err != nil {
			continue
		}
		e.Cmd("Vaciar %s", t)
		e.SetSub("Borrando "+strings.ToLower(it.Name), -1)
		deleteInside(t, res)
	}
	left := int64(0)
	for _, t := range targets {
		left += junkSize(it.Arg, t)
		diskScan.Rescan(t)
	}
	e.Out(fmt.Sprintf("Liberado: %s · quedan %s%s", fmtBytes(res.Freed), fmtBytes(left), ternary(res.Failed > 0, fmt.Sprintf(" (%d archivo(s) en uso)", res.Failed), "")))
	it.Bytes = left
	it.Current = fmtBytes(left)
	if res.Freed == 0 && left > 1<<20 {
		return "", fmt.Errorf("no se ha podido borrar nada: los %s que quedan están en uso por programas abiertos. Cierra los programas (o reinicia) y vuelve a intentarlo", fmtBytes(left))
	}
	it.Detail = fmt.Sprintf("Última limpieza: liberados %s.", fmtBytes(res.Freed)) + ternary(left > 1<<20, " Quedan "+fmtBytes(left)+" en uso por programas abiertos.", "")
	if left > 50<<20 {
		return "Limpiable", nil
	}
	return "Limpio", nil
}

// junkSize mide lo que ocupa un destino de la limpieza rápida.
func junkSize(id, t string) int64 {
	if id == "thumbs" {
		var n int64
		m, _ := filepath.Glob(filepath.Join(t, "thumbcache_*.db"))
		for _, f := range m {
			if fi, err := os.Stat(f); err == nil {
				n += fi.Size()
			}
		}
		return n
	}
	return dirSize(t)
}

// MeasureJunk mide la basura sin PowerShell (antes era un script que tardaba bastante).
func MeasureJunk() []JunkDir {
	out := make([]JunkDir, len(junkOrder))
	var wg sync.WaitGroup
	for i, id := range junkOrder {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			j := JunkDir{ID: id}
			for _, t := range junkTargets(id) {
				j.Bytes += junkSize(id, t)
			}
			if id == "crash" {
				if fi, err := os.Stat(os.Getenv("WINDIR") + `\MEMORY.DMP`); err == nil {
					j.Bytes += fi.Size()
				}
			}
			out[i] = j
		}(i, id)
	}
	wg.Wait()
	return out
}
