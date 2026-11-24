package main

// Explorador de espacio (como SizeTree / WinDirStat): recorre una unidad en paralelo, guarda
// el árbol de carpetas con sus tamaños y responde a la interfaz. Portable (tests en Linux).

import (
	"container/heap"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type DFile struct {
	Name  string
	Size  int64
	MTime int64
}

type DNode struct {
	Name   string
	Path   string
	Size   int64 // total (con subcarpetas)
	Own    int64 // solo los archivos de esta carpeta
	Files  int64 // total de archivos (con subcarpetas)
	MTime  int64
	Denied bool
	Kids   []*DNode
	Big    []DFile // los archivos más grandes de esta carpeta
	Rest   int     // archivos que no están en Big
	Parent *DNode
}

const bigPerDir = 60

type DiskScan struct {
	mu      sync.Mutex
	Root    *DNode
	State   string // "", "escaneando", "listo", "error"
	Err     string
	Started time.Time
	Took    float64
	files   atomic.Int64
	dirs    atomic.Int64
	bytes   atomic.Int64
	denied  atomic.Int64
	cur     atomic.Value
	top     fileHeap
	topMu   sync.Mutex
	cancel  atomic.Bool
	byPath  map[string]*DNode
	gone    map[string]bool // archivos grandes ya borrados (para no volver a enseñarlos)
	Total   uint64
	Free    uint64
}

// ---- los mayores archivos del disco (montículo de los 300 más grandes) ----
type topFile struct {
	Path  string
	Size  int64
	MTime int64
}
type fileHeap []topFile

func (h fileHeap) Len() int           { return len(h) }
func (h fileHeap) Less(i, j int) bool { return h[i].Size < h[j].Size }
func (h fileHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *fileHeap) Push(x any)        { *h = append(*h, x.(topFile)) }
func (h *fileHeap) Pop() any          { o := *h; n := len(o); x := o[n-1]; *h = o[:n-1]; return x }

func (s *DiskScan) addTop(f topFile) {
	s.topMu.Lock()
	defer s.topMu.Unlock()
	if len(s.top) < 300 {
		heap.Push(&s.top, f)
	} else if f.Size > s.top[0].Size {
		s.top[0] = f
		heap.Fix(&s.top, 0)
	}
}

// skipDir: enlaces y puntos de montaje (no se siguen para no contar dos veces ni dar vueltas).
func skipEntry(d fs.DirEntry) bool {
	t := d.Type()
	return t&fs.ModeSymlink != 0 || t&fs.ModeIrregular != 0 || t&fs.ModeDevice != 0
}

// Scan recorre root en paralelo. Bloquea hasta terminar.
func (s *DiskScan) Scan(root string) {
	s.mu.Lock()
	s.State, s.Err, s.Started = "escaneando", "", time.Now()
	s.files.Store(0)
	s.dirs.Store(0)
	s.bytes.Store(0)
	s.denied.Store(0)
	s.cancel.Store(false)
	s.top = nil
	rn := &DNode{Name: root, Path: root}
	s.Root = rn
	s.mu.Unlock()

	sem := make(chan struct{}, 24)
	var wg sync.WaitGroup
	var walk func(n *DNode)
	walk = func(n *DNode) {
		defer wg.Done()
		if s.cancel.Load() {
			return
		}
		sem <- struct{}{}
		entries, err := os.ReadDir(n.Path)
		<-sem
		s.dirs.Add(1)
		s.cur.Store(n.Path)
		if err != nil {
			n.Denied = true
			s.denied.Add(1)
		}
		var big []DFile
		for _, e := range entries {
			if skipEntry(e) {
				continue
			}
			if e.IsDir() {
				k := &DNode{Name: e.Name(), Path: filepath.Join(n.Path, e.Name()), Parent: n}
				if fi, err := e.Info(); err == nil {
					k.MTime = fi.ModTime().Unix()
				}
				n.Kids = append(n.Kids, k)
				continue
			}
			fi, err := e.Info()
			if err != nil {
				continue
			}
			sz := fi.Size()
			mt := fi.ModTime().Unix()
			n.Own += sz
			n.Files++
			if mt > n.MTime {
				n.MTime = mt
			}
			s.files.Add(1)
			s.bytes.Add(sz)
			big = append(big, DFile{e.Name(), sz, mt})
			if sz > 50<<20 {
				s.addTop(topFile{filepath.Join(n.Path, e.Name()), sz, mt})
			}
		}
		sort.Slice(big, func(a, b int) bool { return big[a].Size > big[b].Size })
		if len(big) > bigPerDir {
			n.Rest = len(big) - bigPerDir
			big = big[:bigPerDir]
		}
		n.Big = big
		for _, k := range n.Kids {
			wg.Add(1)
			go walk(k)
		}
	}
	wg.Add(1)
	walk(rn)
	wg.Wait()
	byPath := s.finalize(rn)
	s.mu.Lock()
	s.byPath = byPath
	s.Took = time.Since(s.Started).Seconds()
	if s.cancel.Load() {
		s.State, s.Err = "error", "Cancelado."
	} else {
		s.State = "listo"
	}
	s.mu.Unlock()
}

func (s *DiskScan) Cancel() { s.cancel.Store(true) }

type DiskProgress struct {
	State  string  `json:"state"`
	Err    string  `json:"err,omitempty"`
	Root   string  `json:"root"`
	Files  int64   `json:"files"`
	Dirs   int64   `json:"dirs"`
	Bytes  int64   `json:"bytes"`
	Denied int64   `json:"denied"`
	Cur    string  `json:"cur"`
	Secs   float64 `json:"secs"`
	Total  uint64  `json:"total"`
	Free   uint64  `json:"free"`
}

func (s *DiskScan) Progress() DiskProgress {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := DiskProgress{State: s.State, Err: s.Err, Files: s.files.Load(), Dirs: s.dirs.Load(), Bytes: s.bytes.Load(), Denied: s.denied.Load(), Total: s.Total, Free: s.Free}
	if s.Root != nil {
		p.Root = s.Root.Path
	}
	if c, ok := s.cur.Load().(string); ok {
		p.Cur = c
	}
	if s.State == "escaneando" {
		p.Secs = time.Since(s.Started).Seconds()
	} else {
		p.Secs = s.Took
	}
	return p
}

// ---------- respuestas para la interfaz ----------

type DEntry struct {
	Name   string    `json:"name"`
	Path   string    `json:"path"`
	Dir    bool      `json:"dir"`
	Size   int64     `json:"size"`
	Files  int64     `json:"files"`
	MTime  int64     `json:"mtime"`
	Kids   int       `json:"kids"`
	Denied bool      `json:"denied,omitempty"`
	Class  DiskClass `json:"class"`
	Rest   bool      `json:"rest,omitempty"` // fila "otros archivos"
}

type DView struct {
	Path    string   `json:"path"`
	Crumbs  []DEntry `json:"crumbs"`
	Self    DEntry   `json:"self"`
	Entries []DEntry `json:"entries"`
}

func entryOf(n *DNode) DEntry {
	return DEntry{Name: n.Name, Path: n.Path, Dir: true, Size: n.Size, Files: n.Files, MTime: n.MTime, Kids: len(n.Kids), Denied: n.Denied,
		Class: ClassifyPath(n.Path, true, n.Size, time.Unix(n.MTime, 0))}
}

// View devuelve el contenido de una carpeta (subcarpetas + archivos grandes), ordenado por tamaño.
func (s *DiskScan) View(path string) (DView, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byPath == nil {
		return DView{}, false
	}
	n := s.Root
	if path != "" {
		if x, ok := s.byPath[strings.ToLower(path)]; ok {
			n = x
		}
	}
	v := DView{Path: n.Path, Self: entryOf(n)}
	for p := n; p != nil; p = p.Parent {
		v.Crumbs = append([]DEntry{{Name: p.Name, Path: p.Path, Dir: true, Size: p.Size}}, v.Crumbs...)
	}
	for _, k := range n.Kids {
		v.Entries = append(v.Entries, entryOf(k))
	}
	var restSize int64
	for _, f := range n.Big {
		fp := joinP(n.Path, f.Name)
		v.Entries = append(v.Entries, DEntry{Name: f.Name, Path: fp, Size: f.Size, Files: 1, MTime: f.MTime, Class: ClassifyPath(fp, false, f.Size, time.Unix(f.MTime, 0))})
	}
	if n.Rest > 0 {
		var shown int64
		for _, f := range n.Big {
			shown += f.Size
		}
		restSize = n.Own - shown
		v.Entries = append(v.Entries, DEntry{Name: "Otros " + itoa(n.Rest) + " archivos más pequeños", Path: n.Path, Size: restSize, Files: int64(n.Rest), Rest: true})
	}
	sort.SliceStable(v.Entries, func(a, b int) bool { return v.Entries[a].Size > v.Entries[b].Size })
	return v, true
}

func itoa(n int) string { return fmtInt(int64(n)) }

func fmtInt(n int64) string {
	s := []byte{}
	neg := n < 0
	if neg {
		n = -n
	}
	if n == 0 {
		return "0"
	}
	i := 0
	for n > 0 {
		if i > 0 && i%3 == 0 {
			s = append([]byte{'.'}, s...)
		}
		s = append([]byte{byte('0' + n%10)}, s...)
		n /= 10
		i++
	}
	if neg {
		s = append([]byte{'-'}, s...)
	}
	return string(s)
}

// TopFiles: los archivos más grandes de todo el disco.
func (s *DiskScan) TopFiles(n int) []DEntry {
	s.topMu.Lock()
	l := fileHeap{}
	for _, f := range s.top {
		if !s.gone[strings.ToLower(f.Path)] {
			l = append(l, f)
		}
	}
	s.topMu.Unlock()
	sort.Slice(l, func(a, b int) bool { return l[a].Size > l[b].Size })
	if len(l) > n {
		l = l[:n]
	}
	out := []DEntry{}
	for _, f := range l {
		out = append(out, DEntry{Name: baseP(f.Path), Path: f.Path, Size: f.Size, Files: 1, MTime: f.MTime, Class: ClassifyPath(f.Path, false, f.Size, time.Unix(f.MTime, 0))})
	}
	return out
}

// Recommend: lo que se puede liberar, agrupado (la carpeta más alta de cada regla).
func (s *DiskScan) Recommend() []DEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []DEntry{}
	if s.Root == nil || s.byPath == nil {
		return out
	}
	var walk func(n *DNode)
	walk = func(n *DNode) {
		c := ClassifyPath(n.Path, true, n.Size, time.Unix(n.MTime, 0))
		if (c.Level == LvlBorrar || (c.Level == LvlCuidado && c.Action != "")) && n.Size > 1<<20 {
			e := entryOf(n)
			e.Class = c
			out = append(out, e)
			return
		}
		if c.Level == LvlSistema && c.Action != "" && n.Size > 100<<20 {
			e := entryOf(n)
			out = append(out, e)
			return
		}
		for _, k := range n.Kids {
			walk(k)
		}
		for _, f := range n.Big {
			fp := joinP(n.Path, f.Name)
			fc := ClassifyPath(fp, false, f.Size, time.Unix(f.MTime, 0))
			if (fc.Level == LvlBorrar || fc.Action != "") && f.Size > 1<<20 {
				out = append(out, DEntry{Name: f.Name, Path: fp, Size: f.Size, Files: 1, MTime: f.MTime, Class: fc})
			}
		}
	}
	walk(s.Root)
	sort.Slice(out, func(a, b int) bool { return out[a].Size > out[b].Size })
	return out
}

// ---------- borrar ----------

type DeleteResult struct {
	Freed   int64    `json:"freed"`
	Deleted int      `json:"deleted"`
	Failed  int      `json:"failed"`
	Skipped []string `json:"skipped"`
	Errors  []string `json:"errors"`
}

// CanDelete: nunca se borra nada clasificado como sistema ni la raíz de una unidad o de un perfil.
func CanDelete(path string, isDir bool) (bool, string) {
	l := strings.ToLower(strings.TrimSuffix(strings.ReplaceAll(path, "/", `\`), `\`))
	if len(l) <= 3 {
		return false, "No se puede borrar una unidad entera."
	}
	c := ClassifyPath(path, isDir, 0, time.Now())
	if c.Level == LvlSistema {
		return false, "Es parte del sistema o de un programa instalado."
	}
	if c.Action == "hiber" || c.Action == "storage" || c.Action == "dism" {
		return false, "Se libera con su opción de Windows, no borrando a mano."
	}
	if i := strings.Index(l, `\users\`); i >= 0 {
		rest := l[i+7:]
		if !strings.Contains(rest, `\`) || strings.Count(rest, `\`) == 1 && hasAny(rest, `\appdata`, `\desktop`, `\documents`, `\downloads`, `\pictures`, `\videos`, `\music`, `\onedrive`) {
			return false, "Es la carpeta de un usuario o una de sus carpetas principales: borra lo de dentro, no la carpeta."
		}
	}
	if strings.HasSuffix(l, `\users`) {
		return false, "Es la carpeta de usuarios."
	}
	return true, ""
}

// deleteInside borra el contenido de una carpeta (lo que esté en uso se queda) y mide lo liberado.
func deleteInside(dir string, res *DeleteResult) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		res.Failed++
		res.Errors = append(res.Errors, filepath.Base(dir)+": "+err.Error())
		return
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if strings.EqualFold(e.Name(), "desktop.ini") {
			continue
		}
		if e.IsDir() && !skipEntry(e) {
			deleteInside(p, res)
			if os.Remove(p) == nil {
				res.Deleted++
			}
			continue
		}
		var sz int64
		if fi, err := e.Info(); err == nil {
			sz = fi.Size()
		}
		if err := os.Remove(p); err != nil {
			_ = os.Chmod(p, 0o666) // quita "solo lectura" y reintenta
			if err2 := os.Remove(p); err2 != nil {
				res.Failed++
				continue
			}
		}
		res.Deleted++
		res.Freed += sz
	}
}

// dirSize mide una carpeta (para lo que se manda a la papelera).
func dirSize(p string) int64 {
	var n int64
	_ = filepath.WalkDir(p, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && !skipEntry(d) {
			if fi, e := d.Info(); e == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// ForgetPath quita del árbol lo borrado y resta su tamaño hacia arriba.
func (s *DiskScan) ForgetPath(p string, freed int64, whole bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byPath == nil {
		return
	}
	lp := strings.ToLower(p)
	n, isDir := s.byPath[lp]
	var parent *DNode
	if isDir {
		parent = n.Parent
	} else {
		parent = s.byPath[strings.ToLower(filepath.Dir(p))]
	}
	if isDir && whole && parent != nil {
		for i, k := range parent.Kids {
			if k == n {
				parent.Kids = append(parent.Kids[:i], parent.Kids[i+1:]...)
				break
			}
		}
		delete(s.byPath, lp)
	} else if isDir {
		n.Kids, n.Big, n.Own, n.Rest = nil, nil, 0, 0
		n.Size -= freed
		n.Files = 0
	} else if parent != nil {
		base := filepath.Base(p)
		for i, f := range parent.Big {
			if strings.EqualFold(f.Name, base) {
				parent.Big = append(parent.Big[:i], parent.Big[i+1:]...)
				break
			}
		}
		parent.Own -= freed
	}
	for a := parent; a != nil; a = a.Parent {
		a.Size -= freed
		if a.Size < 0 {
			a.Size = 0
		}
	}
}

// finalize suma los tamaños de abajo arriba, ordena y crea el índice por ruta.
func (s *DiskScan) finalize(rn *DNode) map[string]*DNode {
	var sum func(n *DNode)
	byPath := map[string]*DNode{}
	sum = func(n *DNode) {
		byPath[strings.ToLower(n.Path)] = n
		n.Size = n.Own
		for _, k := range n.Kids {
			sum(k)
			n.Size += k.Size
			n.Files += k.Files
			if k.MTime > n.MTime {
				n.MTime = k.MTime
			}
		}
		sort.Slice(n.Kids, func(a, b int) bool { return n.Kids[a].Size > n.Kids[b].Size })
	}
	sum(rn)
	return byPath
}

// joinP une ruta y nombre respetando el separador de la ruta (también en los tests de Linux).
func joinP(dir, name string) string {
	if strings.Contains(dir, `\`) {
		return strings.TrimSuffix(dir, `\`) + `\` + name
	}
	return filepath.Join(dir, name)
}

func baseP(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// Rescan vuelve a medir una carpeta o archivo de verdad (después de borrar o limpiar) y
// corrige el árbol y los totales hacia arriba. Así lo que se ve es lo que queda en el disco.
func (s *DiskScan) Rescan(p string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byPath == nil {
		return
	}
	lp := strings.ToLower(p)
	fi, statErr := os.Lstat(p)
	if n, ok := s.byPath[lp]; ok { // carpeta conocida
		old := n.Size
		parent := n.Parent
		for k := range s.byPath {
			if k == lp || strings.HasPrefix(k, lp+`\`) || strings.HasPrefix(k, lp+"/") {
				delete(s.byPath, k)
			}
		}
		var newSize int64
		if statErr == nil && fi.IsDir() {
			fresh := scanTree(p, n.Name, parent)
			for k, v := range s.finalizeSub(fresh) {
				s.byPath[k] = v
			}
			newSize = fresh.Size
			if parent != nil {
				for i, k := range parent.Kids {
					if k == n {
						parent.Kids[i] = fresh
					}
				}
			} else {
				s.Root = fresh
			}
		} else if parent != nil {
			for i, k := range parent.Kids {
				if k == n {
					parent.Kids = append(parent.Kids[:i], parent.Kids[i+1:]...)
					break
				}
			}
		}
		s.adjustUp(parent, newSize-old)
		return
	}
	// archivo
	parent := s.byPath[strings.ToLower(parentP(p))]
	if parent == nil {
		return
	}
	base := baseP(p)
	for i, f := range parent.Big {
		if strings.EqualFold(f.Name, base) {
			var now int64
			if statErr == nil {
				now = fi.Size()
				parent.Big[i].Size = now
			} else {
				parent.Big = append(parent.Big[:i], parent.Big[i+1:]...)
				s.topMu.Lock()
				if s.gone == nil {
					s.gone = map[string]bool{}
				}
				s.gone[lp] = true
				s.topMu.Unlock()
			}
			delta := now - f.Size
			parent.Own += delta
			parent.Size += delta
			s.adjustUp(parent.Parent, delta)
			return
		}
	}
}

func (s *DiskScan) adjustUp(n *DNode, delta int64) {
	for a := n; a != nil; a = a.Parent {
		a.Size += delta
		if a.Size < 0 {
			a.Size = 0
		}
	}
}

// finalizeSub suma y ordena un subárbol recién leído y devuelve su índice por ruta.
func (s *DiskScan) finalizeSub(rn *DNode) map[string]*DNode {
	return s.finalize(rn)
}

// scanTree lee una carpeta entera (sin paralelismo: es para carpetas ya conocidas).
func scanTree(path, name string, parent *DNode) *DNode {
	n := &DNode{Name: name, Path: path, Parent: parent}
	entries, err := os.ReadDir(path)
	if err != nil {
		n.Denied = true
		return n
	}
	var big []DFile
	for _, e := range entries {
		if skipEntry(e) {
			continue
		}
		if e.IsDir() {
			n.Kids = append(n.Kids, scanTree(joinP(path, e.Name()), e.Name(), n))
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		n.Own += fi.Size()
		n.Files++
		mt := fi.ModTime().Unix()
		if mt > n.MTime {
			n.MTime = mt
		}
		big = append(big, DFile{e.Name(), fi.Size(), mt})
	}
	sort.Slice(big, func(a, b int) bool { return big[a].Size > big[b].Size })
	if len(big) > bigPerDir {
		n.Rest = len(big) - bigPerDir
		big = big[:bigPerDir]
	}
	n.Big = big
	return n
}

func parentP(p string) string {
	i := strings.LastIndexAny(p, `\/`)
	if i <= 0 {
		return p
	}
	if i == 2 && p[1] == ':' {
		return p[:3]
	}
	return p[:i]
}
