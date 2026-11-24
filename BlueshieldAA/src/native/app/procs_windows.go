//go:build windows

package main

import (
	"os"
	"strings"
	"time"
)

func Processes() ProcOut {
	collector.touch() // CPU por proceso (contadores de rendimiento)
	nc := map[int]int{}
	for _, c := range NetConns(false) {
		if c.State == "Established" {
			nc[c.PID]++
		}
	}
	cpu := map[int]float64{}
	collector.mu.Lock()
	for _, p := range collector.procs {
		cpu[p.PID] = p.C
	}
	collector.mu.Unlock()
	out := ProcOut{}
	var rows []ProcRow
	for _, p := range ProcList(true) {
		r := ProcRow{PID: p.PID, PPID: p.PPID, Name: p.Name, Path: p.Path, Cmd: p.Cmd, User: p.User, Mem: p.Mem, CPU: round1(cpu[p.PID]), Conns: nc[p.PID]}
		if !p.Start.IsZero() && p.Start.Year() > 2000 {
			r.Start = p.Start.Format(time.RFC3339)
		}
		if p.Path != "" {
			m := FileMeta(p.Path)
			r.Company, r.Desc, r.Signed, r.Signer = m.Company, m.Desc, m.Signed, m.Signer
		}
		ClassifyProc(&r)
		if r.Signed == "Sin firmar" {
			out.Unsigned++
		}
		if r.Flag != "" {
			out.Flagged++
		}
		if r.Conns > 0 {
			out.Net++
		}
		rows = append(rows, r)
	}
	out.Procs = ProcTree(rows)
	out.Total = len(rows)
	return out
}

// ProcKill termina un proceso a petición del usuario (nunca los críticos de Windows).
func ProcKill(e *Engine, pid int, name string) string {
	if pid <= 4 || pid == os.Getpid() || IsCritical(name) {
		return "Ese proceso es parte de Windows y no se puede terminar desde aquí."
	}
	var cur *nProc
	for _, p := range ProcList(false) {
		if p.PID == pid {
			cur = &p
			break
		}
	}
	if cur == nil {
		return "Ese proceso ya no está en marcha."
	}
	if !strings.EqualFold(strings.TrimSuffix(cur.Name, ".exe"), strings.TrimSuffix(name, ".exe")) {
		return "Ese número de proceso ya corresponde a otro programa; no se ha tocado nada."
	}
	e.Log("cmd", "> Terminar proceso %d (%s)", pid, name)
	if err := KillPID(pid); err != nil {
		return "No se pudo terminar: " + err.Error()
	}
	e.Log("ok", "✔ Proceso %s (%d) terminado a petición del usuario.", name, pid)
	return ""
}
