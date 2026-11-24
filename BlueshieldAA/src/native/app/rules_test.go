package main

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if err := LoadRules("reglas/reglas-analisis.json"); err != nil {
		panic(err)
	}
	postRunRefresh = false
	os.Exit(m.Run())
}
