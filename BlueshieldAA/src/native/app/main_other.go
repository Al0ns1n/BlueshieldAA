//go:build !windows

package main

import "fmt"

// BlueShieldAA solo funciona en Windows; en otros sistemas solo se compila para los tests.
func main() { fmt.Println("BlueShieldAA solo funciona en Windows 10/11.") }
