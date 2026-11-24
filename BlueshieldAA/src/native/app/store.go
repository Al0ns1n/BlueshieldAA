package main

// Datos persistentes de BlueShieldAA 4.x: ajustes, último análisis, historial y puntuaciones.
// Todo en JSON dentro de la carpeta de datos (ProgramData, o "datos" en la versión portable).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const AppVersion = "4.2.1"
const AppName = "BlueShieldAA"

// Settings: lo que el usuario puede cambiar en Ajustes.
type Settings struct {
	WU      bool `json:"wu"`      // incluir Windows Update
	Pip     bool `json:"pip"`     // revisar paquetes de Python
	Scout   bool `json:"scout"`   // revisar imágenes Docker
	Restore bool `json:"restore"` // punto de restauración antes de cambios
	Secrets bool `json:"secrets"` // buscar archivos con contraseñas
}

type ServerCfg struct {
	Enabled   bool   `json:"enabled"`
	URL       string `json:"url"`
	Realm     string `json:"realm"`
	ClientID  string `json:"clientId"`
	Webhook   string `json:"webhook"`
	HasSecret bool   `json:"hasSecret"`
}

type Config struct {
	Settings  Settings          `json:"settings"`
	Theme     string            `json:"theme"`
	Projects  []string          `json:"projects"`
	Domains   []string          `json:"domains"`
	Backups   []string          `json:"backups"`
	UpdateURL string            `json:"updateURL"`
	Server    ServerCfg         `json:"server"`
	NvdKey    string            `json:"nvdKey,omitempty"`
	Dismissed map[string]bool   `json:"dismissed"`
	Excluded  map[string]bool   `json:"excluded"` // ids de winget que no se actualizan aquí
	Checked   map[string]bool   `json:"checked"`
	Extra     map[string]string `json:"extra,omitempty"`
}

func defaultConfig() Config {
	return Config{
		Settings:  Settings{WU: true, Pip: true, Restore: true},
		Theme:     "light",
		Dismissed: map[string]bool{},
		Excluded:  map[string]bool{},
		Checked:   map[string]bool{},
	}
}

type HistEntry struct {
	When     string `json:"when"`
	Name     string `json:"name"`
	WingetID string `json:"wingetId"`
	Source   string `json:"source"`
	From     string `json:"from"`
	To       string `json:"to"`
	Result   string `json:"result"`
	Undone   bool   `json:"undone"`
}

type ScorePoint struct {
	T string `json:"t"`
	S int    `json:"s"`
}

type Saved struct {
	When  time.Time `json:"when"`
	Items []*Item   `json:"items"`
}

type Store struct {
	mu    sync.Mutex // historial y puntuaciones
	cfgMu sync.Mutex // ajustes (Cfg): SIEMPRE con este cerrojo, nunca a pelo
	Dir   string
	Cfg   Config
	Hist  []HistEntry
	Pts   []ScorePoint
}

func NewStore(dir string) *Store {
	_ = os.MkdirAll(dir, 0o755)
	s := &Store{Dir: dir, Cfg: defaultConfig()}
	_ = readJSON(filepath.Join(dir, "config.json"), &s.Cfg)
	if s.Cfg.Dismissed == nil {
		s.Cfg.Dismissed = map[string]bool{}
	}
	if s.Cfg.Excluded == nil {
		s.Cfg.Excluded = map[string]bool{}
	}
	if s.Cfg.Checked == nil {
		s.Cfg.Checked = map[string]bool{}
	}
	_ = readJSON(filepath.Join(dir, "historial.json"), &s.Hist)
	_ = readJSON(filepath.Join(dir, "puntuacion.json"), &s.Pts)
	return s
}

func (s *Store) Path(parts ...string) string {
	return filepath.Join(append([]string{s.Dir}, parts...)...)
}

func (s *Store) SaveConfig() {
	s.cfgMu.Lock()
	b, err := json.MarshalIndent(s.Cfg, "", " ")
	s.cfgMu.Unlock()
	if err == nil {
		_ = writeRaw(s.Path("config.json"), b)
	}
}

// WithCfg da acceso a los ajustes con el cerrojo puesto (sin guardar).
func (s *Store) WithCfg(f func(c *Config)) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	f(&s.Cfg)
}

// UpdateCfg cambia los ajustes y los guarda.
func (s *Store) UpdateCfg(f func(c *Config)) {
	s.WithCfg(f)
	s.SaveConfig()
}

func (s *Store) AddHist(e HistEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.When == "" {
		e.When = time.Now().Format("2006-01-02 15:04")
	}
	s.Hist = append([]HistEntry{e}, s.Hist...)
	if len(s.Hist) > 500 {
		s.Hist = s.Hist[:500]
	}
	_ = writeJSON(s.Path("historial.json"), s.Hist)
}

func (s *Store) AddScore(v int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Pts = append(s.Pts, ScorePoint{T: time.Now().Format(time.RFC3339), S: v})
	if len(s.Pts) > 200 {
		s.Pts = s.Pts[len(s.Pts)-200:]
	}
	_ = writeJSON(s.Path("puntuacion.json"), s.Pts)
}

// SaveItems recibe una copia (Engine.Items devuelve copias) para no leer mientras se cambian.
func (s *Store) SaveItems(items []*Item) {
	_ = writeJSON(s.Path("ultimo-analisis.json"), Saved{When: time.Now(), Items: items})
}

func (s *Store) LoadItems() (Saved, bool) {
	var sv Saved
	if err := readJSON(s.Path("ultimo-analisis.json"), &sv); err != nil || len(sv.Items) == 0 {
		return sv, false
	}
	return sv, true
}

func readJSON(p string, v any) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// writeJSON escribe de forma atómica (archivo temporal + renombrar).
func writeJSON(p string, v any) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	return writeRaw(p, b)
}

func writeRaw(p string, b []byte) error {
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
