//go:build windows

package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

func (a *App) guardFiles() guardFiles { return guardFiles{a.St.Dir} }

func (a *App) bindGuard(b func(string, any)) {
	e := a.E
	g := a.guardFiles()
	who := func() string {
		if u, err := user.Current(); err == nil {
			return u.Username
		}
		return "administrador"
	}

	b("caDecoyStatus", func() map[string]any { return guardStatus(g, a.portable) })

	b("caDecoyEnable", func(on bool) string {
		if a.portable {
			return "El anti-ransomware solo funciona en la versión instalada: necesita un guardián que arranque con Windows."
		}
		if !isAdmin() {
			return "Hace falta abrir BlueShieldAA como administrador."
		}
		defer resetTaskCache()
		if on {
			cfg := g.cfg()
			cfg.Enabled = true
			cfg.InstallDir = filepath.Dir(selfExe())
			if cfg.Marker == "" {
				cfg.Marker = strings.ToUpper(randID()[:8])
			}
			if err := g.saveCfg(cfg); err != nil {
				return "No se pudo guardar la configuración: " + err.Error()
			}
			_ = os.MkdirAll(g.p("ordenes"), 0o755)
			if err := installGuardTask(); err != nil {
				return err.Error()
			}
			e.Log("info", "Anti-ransomware activado en modo %s", cfg.Mode)
			return ""
		}
		if g.cont().Active {
			return "El equipo está en contención: primero hay que liberarlo."
		}
		cfg := g.cfg()
		cfg.Enabled = false
		_ = g.saveCfg(cfg)
		// el guardián quita los señuelos y se para solo; si no responde, se hace desde aquí
		for i := 0; i < 16 && g.running(); i++ {
			time.Sleep(500 * time.Millisecond)
			if len(g.rt().Decoys) == 0 {
				break
			}
		}
		removeGuardTask()
		if rt := g.rt(); len(rt.Decoys) > 0 {
			removeDecoys(rt.Decoys)
			rt.Decoys, rt.Folders = nil, nil
			g.saveRt(rt)
		}
		e.Log("info", "Anti-ransomware desactivado y señuelos quitados")
		return ""
	})

	b("caGuardMode", func(mode string) string {
		if mode != "contener" {
			mode = "simulacro"
		}
		cfg := g.cfg()
		cfg.Mode = mode
		if err := g.saveCfg(cfg); err != nil {
			return err.Error()
		}
		e.Log("info", "Anti-ransomware en modo %s", mode)
		return ""
	})

	b("caDecoyOptions", func(isolate, stopSvc, lockdown bool) string {
		cfg := g.cfg()
		cfg.Isolate, cfg.StopSvc, cfg.Lockdown = isolate, stopSvc, lockdown
		if err := g.saveCfg(cfg); err != nil {
			return err.Error()
		}
		return ""
	})

	b("caDecoyAddFolder", func() string {
		p := pickFolder(a.hwnd, "Carpeta local donde poner documentos trampa")
		if p == "" {
			return ""
		}
		if strings.HasPrefix(p, `\\`) {
			return "ERROR:Es una carpeta de red. Solo se admiten carpetas locales de este equipo."
		}
		if ok, why := FolderAllowed(p); !ok {
			return "ERROR:No se admite porque " + why + "."
		}
		cfg := g.cfg()
		for _, c := range cfg.Custom {
			if strings.EqualFold(c, p) {
				return p
			}
		}
		cfg.Custom = append(cfg.Custom, p)
		_ = g.saveCfg(cfg)
		_ = g.order(GuardOrder{Cmd: "resembrar"})
		return p
	})

	b("caDecoyRemoveFolder", func(p string) string {
		cfg := g.cfg()
		var l []string
		for _, c := range cfg.Custom {
			if !strings.EqualFold(c, p) {
				l = append(l, c)
			}
		}
		cfg.Custom = l
		_ = g.saveCfg(cfg)
		_ = g.order(GuardOrder{Cmd: "resembrar"})
		return ""
	})

	b("caDecoyTest", func() string {
		if !g.running() {
			return "El guardián no está en marcha."
		}
		if err := g.order(GuardOrder{Cmd: "prueba"}); err != nil {
			return err.Error()
		}
		return ""
	})

	b("caDecoyResolve", func(id string) string {
		if g.running() {
			_ = g.order(GuardOrder{Cmd: "resolver", Arg: id})
		} else {
			g.updateIncident(id, func(i *GuardIncident) { i.Resolved = true })
		}
		return ""
	})

	b("caGuardChecks", func(reviewed, externalAV bool) map[string]any { return guardChecks(g, reviewed, externalAV) })
	b("caGuardScan", func() string { return startDefenderScan(g) })
	b("caGuardOffline", func() string {
		_, err := runPS("Start-MpWDOScan", 60*time.Second)
		if err != nil {
			return "No se pudo programar el análisis sin conexión: " + err.Error()
		}
		return ""
	})
	b("caGuardRelease", func(confirm string, reviewed, externalAV bool) string {
		if strings.TrimSpace(strings.ToUpper(confirm)) != "LIBERAR" {
			return "Escribe LIBERAR para confirmar."
		}
		r := guardChecks(g, reviewed, externalAV)
		if can, _ := r["can"].(bool); !can {
			return "Aún faltan comprobaciones obligatorias."
		}
		by := who()
		e.Log("warn", "Liberando el equipo de la contención (%s)", by)
		if g.running() {
			_ = g.order(GuardOrder{Cmd: "liberar", By: by})
			for i := 0; i < 120 && g.cont().Active; i++ {
				time.Sleep(500 * time.Millisecond)
			}
			if !g.cont().Active {
				return ""
			}
		}
		if errs := releaseContainment(g, by); len(errs) > 0 {
			return "Liberado con avisos: " + strings.Join(errs, " · ")
		}
		return ""
	})
	b("caGuardLog", func() string {
		bb, _ := os.ReadFile(g.p("guardian.log"))
		if len(bb) > 64<<10 {
			bb = bb[len(bb)-64<<10:]
		}
		return string(bb)
	})
	b("caGuardOpenEscape", func() { reveal(filepath.Join(filepath.Dir(selfExe()), "desbloquear.cmd")) })
}

// guardCLI: --liberar (desbloquear.cmd) y --desinstalar (desinstalador).
func guardCLI(arg string) {
	dir, portable := dataDir()
	if portable {
		return
	}
	_ = LoadRules(filepath.Join(filepath.Dir(selfExe()), "reglas-analisis.json"))
	g := guardFiles{dir}
	if arg == "--liberar" {
		releaseContainment(g, "desbloquear.cmd")
		return
	}
	// --desinstalar: se quita todo lo que deja el anti-ransomware
	removeGuardTask()
	releaseContainment(g, "desinstalador")
	if rt := g.rt(); len(rt.Decoys) > 0 {
		removeDecoys(rt.Decoys)
		rt.Decoys, rt.Folders = nil, nil
		g.saveRt(rt)
	}
	cfg := g.cfg()
	cfg.Enabled = false
	_ = g.saveCfg(cfg)
}
