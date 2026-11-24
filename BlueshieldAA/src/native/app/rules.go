package main

// Reglas del motor de análisis: listas de textos que se buscan en el código que se ejecuta.
// Van en un archivo de datos aparte (reglas-analisis.json, junto al programa), igual que las
// definiciones de un antivirus, y no dentro del ejecutable.

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

var rulesMu sync.RWMutex
var rules map[string][]string

// LoadRules carga las reglas. Si faltan, el análisis de archivos avisa y no puntúa.
func LoadRules(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var v struct {
		Reglas map[string][]string `json:"reglas"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("reglas no válidas: %w", err)
	}
	if len(v.Reglas) == 0 {
		return fmt.Errorf("el archivo de reglas está vacío")
	}
	rulesMu.Lock()
	rules = v.Reglas
	rulesMu.Unlock()
	return nil
}

func RulesLoaded() bool { rulesMu.RLock(); defer rulesMu.RUnlock(); return len(rules) > 0 }

func rule(k string) []string { rulesMu.RLock(); defer rulesMu.RUnlock(); return rules[k] }

func hasAnyR(s, k string) bool  { return hasAny(s, rule(k)...) }
func hasAllR(s, k string) bool  { l := rule(k); return len(l) > 0 && hasAll(s, l...) }
func countAnyR(s, k string) int { return countAny(s, rule(k)...) }
