package main

// Clasificación de carpetas y archivos para el explorador de espacio: qué se puede borrar,
// qué conviene revisar, qué es personal y qué es del sistema. Portable y con tests.

import (
	"path/filepath"
	"strings"
	"time"
)

const (
	LvlBorrar   = "borrar"   // se puede borrar sin perder nada (se regenera solo)
	LvlCuidado  = "cuidado"  // probablemente sobra, pero revisa antes
	LvlPersonal = "personal" // tus archivos: decides tú
	LvlSistema  = "sistema"  // no se borra desde aquí
	LvlNormal   = ""         // sin nada especial (programas, datos de apps…)
)

type DiskClass struct {
	Level  string `json:"level"`
	Why    string `json:"why"`
	Action string `json:"action,omitempty"` // acción especial en vez de borrar: hiber, dism, storage, recycle
	Inside bool   `json:"inside,omitempty"` // borrar el CONTENIDO (la carpeta se queda)
}

type pathRule struct {
	contains string // trozo de ruta en minúsculas con \ (o sufijo si empieza por $)
	class    DiskClass
}

// Reglas de "se puede borrar": cachés y temporales que Windows o el programa regeneran.
var safeRules = []pathRule{
	{`\$recycle.bin`, DiskClass{LvlBorrar, "Papelera de reciclaje (de todos los usuarios del equipo).", "", true}},
	{`\windows\temp`, DiskClass{LvlBorrar, "Temporales de Windows y de instaladores.", "", true}},
	{`\appdata\local\temp`, DiskClass{LvlBorrar, "Temporales del usuario. Se borra lo que no esté en uso.", "", true}},
	{`\windows\softwaredistribution\download`, DiskClass{LvlBorrar, "Actualizaciones de Windows ya descargadas e instaladas.", "", true}},
	{`\windows\serviceprofiles\networkservice\appdata\local\microsoft\windows\deliveryoptimization`, DiskClass{LvlBorrar, "Trozos de actualizaciones que Windows comparte con otros equipos.", "", true}},
	{`\programdata\microsoft\windows\wer`, DiskClass{LvlBorrar, "Informes de errores de Windows.", "", true}},
	{`\windows\minidump`, DiskClass{LvlBorrar, "Volcados de pantallazos azules antiguos.", "", true}},
	{`\windows\livekernelreports`, DiskClass{LvlBorrar, "Informes de errores del núcleo.", "", true}},
	{`\appdata\local\crashdumps`, DiskClass{LvlBorrar, "Volcados de programas que se cerraron solos.", "", true}},
	{`\appdata\local\microsoft\windows\inetcache`, DiskClass{LvlBorrar, "Caché de Internet de Windows.", "", true}},
	{`\appdata\local\microsoft\windows\explorer`, DiskClass{LvlBorrar, "Caché de miniaturas e iconos; Windows la vuelve a crear.", "", true}},
	{`\appdata\local\d3dscache`, DiskClass{LvlBorrar, "Caché de sombreadores de DirectX; se regenera.", "", true}},
	{`\appdata\local\nvidia\dxcache`, DiskClass{LvlBorrar, "Caché de sombreadores de NVIDIA; se regenera.", "", true}},
	{`\appdata\local\nvidia\glcache`, DiskClass{LvlBorrar, "Caché de sombreadores de NVIDIA; se regenera.", "", true}},
	{`\appdata\local\amd\dxcache`, DiskClass{LvlBorrar, "Caché de sombreadores de AMD; se regenera.", "", true}},
	{`\programdata\nvidia corporation\downloader`, DiskClass{LvlBorrar, "Instaladores de controladores de NVIDIA ya usados.", "", true}},
	{`\appdata\local\npm-cache`, DiskClass{LvlBorrar, "Caché de npm; se vuelve a descargar si hace falta.", "", true}},
	{`\appdata\local\pip\cache`, DiskClass{LvlBorrar, "Caché de pip (Python).", "", true}},
	{`\appdata\local\yarn\cache`, DiskClass{LvlBorrar, "Caché de Yarn.", "", true}},
	{`\appdata\local\go-build`, DiskClass{LvlBorrar, "Caché de compilación de Go.", "", true}},
	{`\appdata\local\nuget\v3-cache`, DiskClass{LvlBorrar, "Caché de NuGet.", "", true}},
	{`\.gradle\caches`, DiskClass{LvlBorrar, "Caché de Gradle.", "", true}},
	{`\steamapps\shadercache`, DiskClass{LvlBorrar, "Caché de sombreadores de Steam; se regenera al jugar.", "", true}},
	// navegadores y apps de mensajería: solo las cachés
	{`\cache\cache_data`, DiskClass{LvlBorrar, "Caché del navegador o de la aplicación; se vuelve a descargar.", "", true}},
	{`\code cache`, DiskClass{LvlBorrar, "Caché de código del navegador o de la aplicación.", "", true}},
	{`\gpucache`, DiskClass{LvlBorrar, "Caché de la tarjeta gráfica del navegador o de la aplicación.", "", true}},
	{`\grshadercache`, DiskClass{LvlBorrar, "Caché de sombreadores del navegador.", "", true}},
	{`\shadercache`, DiskClass{LvlBorrar, "Caché de sombreadores.", "", true}},
	{`\service worker\cachestorage`, DiskClass{LvlBorrar, "Datos guardados por webs para funcionar sin conexión; se regeneran.", "", true}},
}

// Reglas de "revisa antes": probablemente sobra, pero puede ser algo que quieres.
var careRules = []pathRule{
	{`\node_modules`, DiskClass{LvlCuidado, "Dependencias de un proyecto de Node.js: se vuelven a crear con «npm install».", "", false}},
	{`\appdata\local\docker\wsl`, DiskClass{LvlCuidado, "Discos de Docker Desktop. Límpialo desde Docker (docker system prune), no a mano.", "", false}},
	{`\.android\avd`, DiskClass{LvlCuidado, "Emuladores de Android. Bórralos desde Android Studio si no los usas.", "", false}},
	{`\windows\installer\$patchcache$`, DiskClass{LvlSistema, "Copias de parches de Windows Installer: no se borran a mano.", "", false}},
}

var userPersonal = []string{`\desktop`, `\documents`, `\pictures`, `\videos`, `\music`, `\onedrive`, `\escritorio`, `\documentos`, `\imágenes`, `\vídeos`, `\música`}

var installerExts = map[string]bool{".exe": true, ".msi": true, ".iso": true, ".zip": true, ".7z": true, ".rar": true, ".msix": true, ".appx": true, ".img": true}
var bigMediaExts = map[string]bool{".iso": true, ".vhd": true, ".vhdx": true, ".vmdk": true, ".mkv": true, ".mp4": true, ".mov": true, ".avi": true}

// ClassifyPath decide qué es una ruta. p es la ruta completa (C:\…).
func ClassifyPath(p string, isDir bool, size int64, mtime time.Time) DiskClass {
	l := strings.ToLower(strings.ReplaceAll(p, "/", `\`))
	l = strings.TrimSuffix(l, `\`)
	base := filepath.Base(strings.ReplaceAll(l, `\`, "/"))
	drive := len(l) >= 2 && l[1] == ':'
	root := ""
	if drive {
		root = l[:2]
	}
	// archivos especiales en la raíz
	if !isDir && drive {
		switch l {
		case root + `\hiberfil.sys`:
			return DiskClass{LvlCuidado, "Archivo de hibernación. Se quita desactivando la hibernación (perderás el «inicio rápido» y la opción Hibernar).", "hiber", false}
		case root + `\pagefile.sys`, root + `\swapfile.sys`:
			return DiskClass{LvlSistema, "Memoria virtual de Windows. No se borra.", "", false}
		}
		if l == root+`\windows\memory.dmp` {
			return DiskClass{LvlBorrar, "Volcado de memoria del último pantallazo azul.", "", false}
		}
	}
	if drive && (l == root+`\windows.old` || strings.HasPrefix(l, root+`\windows.old\`)) {
		return DiskClass{LvlBorrar, "Copia de la versión anterior de Windows. Solo sirve para volver atrás tras una actualización grande; se borra con la herramienta de Windows.", "storage", false}
	}
	if strings.Contains(l, `\windows\winsxs`) {
		return DiskClass{LvlSistema, "Componentes de Windows. No se borra a mano: usa «Limpiar componentes» (DISM), que quita solo lo que ya no hace falta.", "dism", false}
	}
	// Firefox: solo cache2
	if strings.Contains(l, `\mozilla\firefox\profiles\`) && strings.Contains(l, `\cache2`) {
		return DiskClass{LvlBorrar, "Caché de Firefox; se vuelve a descargar.", "", true}
	}
	for _, r := range safeRules {
		if r.class.Level == "" {
			continue
		}
		if i := strings.Index(l, r.contains); i >= 0 {
			// la regla tiene que coincidir con un nombre completo de carpeta
			end := i + len(r.contains)
			if end == len(l) || l[end] == '\\' {
				c := r.class
				if end < len(l) {
					c.Inside = false // ya estamos dentro: se borra el elemento tal cual
				}
				return c
			}
		}
	}
	for _, r := range careRules {
		if i := strings.Index(l, r.contains); i >= 0 {
			end := i + len(r.contains)
			if end == len(l) || l[end] == '\\' {
				return r.class
			}
		}
	}
	// sistema
	if drive {
		for _, s := range []string{`\windows`, `\program files`, `\program files (x86)`, `\programdata`, `\system volume information`, `\recovery`, `\boot`, `\$windows.~bt`, `\$windows.~ws`, `\$winreagent`, `\msocache`, `\perflogs`} {
			if l == root+s || strings.HasPrefix(l, root+s+`\`) {
				return DiskClass{LvlSistema, "Parte de Windows o de un programa instalado. Para liberar espacio, desinstala el programa desde Configuración.", "", false}
			}
		}
		if l == root+`\users` || l == root || l == root+`\users\public` || l == root+`\users\default` {
			return DiskClass{LvlNormal, "", "", false}
		}
	}
	// carpetas de usuario
	if i := strings.Index(l, `\users\`); i >= 0 {
		rest := l[i+len(`\users\`):]
		parts := strings.SplitN(rest, `\`, 3)
		if len(parts) >= 2 {
			sub := `\` + parts[1]
			if sub == `\downloads` || sub == `\descargas` {
				ext := strings.ToLower(filepath.Ext(base))
				if !isDir && installerExts[ext] && time.Since(mtime) > 30*24*time.Hour {
					return DiskClass{LvlCuidado, "Instalador o comprimido descargado hace más de un mes: lo normal es que ya no haga falta.", "", false}
				}
				return DiskClass{LvlPersonal, "En Descargas. Revisa si aún lo necesitas.", "", false}
			}
			for _, s := range userPersonal {
				if sub == s {
					if !isDir && bigMediaExts[strings.ToLower(filepath.Ext(base))] && size > 1<<30 {
						return DiskClass{LvlPersonal, "Archivo grande personal (vídeo o imagen de disco). Bórralo solo si ya no lo necesitas.", "", false}
					}
					return DiskClass{LvlPersonal, "Tus archivos personales: decide tú.", "", false}
				}
			}
			if sub == `\appdata` {
				return DiskClass{LvlNormal, "Datos y configuración de los programas. No borres carpetas a mano: desinstala el programa o usa su opción para limpiar.", "", false}
			}
		}
	}
	if !isDir && bigMediaExts[strings.ToLower(filepath.Ext(base))] && size > 2<<30 {
		return DiskClass{LvlCuidado, "Imagen de disco o vídeo muy grande. Comprueba si aún lo necesitas.", "", false}
	}
	return DiskClass{}
}
