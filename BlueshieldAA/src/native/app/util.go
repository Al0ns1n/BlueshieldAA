package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func log2f(x float64) float64   { return math.Log2(x) }
func minf(a, b float64) float64 { return math.Min(a, b) }
func pow2(x float64) float64    { return math.Pow(2, x) }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func fmtBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// ---------- cuarentena (archivos transformados para que no se puedan ejecutar) ----------

type QItem struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Original string   `json:"original"`
	When     string   `json:"when"`
	Size     int64    `json:"size"`
	SHA256   string   `json:"sha256"`
	Verdict  string   `json:"verdict"`
	Reasons  []string `json:"reasons"`
}

const qKey = 0xA7

func qDir(st *Store) string { return st.Path("cuarentena") }

func QuarantineList(st *Store) []QItem {
	var l []QItem
	_ = readJSON(filepath.Join(qDir(st), "indice.json"), &l)
	if l == nil {
		l = []QItem{}
	}
	return l
}

func qSave(st *Store, l []QItem) error { return writeJSON(filepath.Join(qDir(st), "indice.json"), l) }

func xorCopy(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 64<<10)
	var n int64
	for {
		k, err := src.Read(buf)
		for i := 0; i < k; i++ {
			buf[i] ^= qKey
		}
		if k > 0 {
			if _, werr := dst.Write(buf[:k]); werr != nil {
				return n, werr
			}
			n += int64(k)
		}
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
}

// Quarantine mueve el archivo a la cuarentena transformado. Devuelve "" si todo fue bien.
func Quarantine(st *Store, path string, r *FAResult) string {
	src, err := os.Open(path)
	if err != nil {
		return "No se pudo abrir el archivo: " + err.Error()
	}
	id := randID()
	_ = os.MkdirAll(qDir(st), 0o700)
	dstp := filepath.Join(qDir(st), id+".bsq")
	dst, err := os.Create(dstp)
	if err != nil {
		src.Close()
		return "No se pudo escribir en la cuarentena: " + err.Error()
	}
	n, err := xorCopy(dst, src)
	src.Close()
	dst.Close()
	if err != nil {
		os.Remove(dstp)
		return "No se pudo copiar el archivo: " + err.Error()
	}
	if err := os.Remove(path); err != nil {
		os.Remove(dstp)
		return "El archivo está en uso o protegido y no se ha podido quitar de su carpeta. Ciérralo e inténtalo de nuevo."
	}
	q := QItem{ID: id, Name: filepath.Base(path), Original: path, When: time.Now().Format(time.RFC3339), Size: n, Reasons: []string{}}
	if r != nil {
		q.SHA256, q.Verdict = r.SHA256, r.Verdict
		for _, f := range r.Findings {
			if f.Points >= 20 {
				q.Reasons = append(q.Reasons, f.Title)
			}
		}
	}
	l := append([]QItem{q}, QuarantineList(st)...)
	_ = qSave(st, l)
	return ""
}

// QuarantineRestore devuelve la ruta restaurada o "ERROR:motivo".
func QuarantineRestore(st *Store, id string) string {
	l := QuarantineList(st)
	for i, q := range l {
		if q.ID != id {
			continue
		}
		dest := q.Original
		if _, err := os.Stat(dest); err == nil {
			ext := filepath.Ext(dest)
			dest = strings.TrimSuffix(dest, ext) + " (restaurado)" + ext
		}
		_ = os.MkdirAll(filepath.Dir(dest), 0o755)
		src, err := os.Open(filepath.Join(qDir(st), id+".bsq"))
		if err != nil {
			return "ERROR:No se encuentra el archivo en la cuarentena."
		}
		dst, err := os.Create(dest)
		if err != nil {
			src.Close()
			return "ERROR:No se puede escribir en " + filepath.Dir(dest)
		}
		_, err = xorCopy(dst, src)
		src.Close()
		dst.Close()
		if err != nil {
			return "ERROR:" + err.Error()
		}
		os.Remove(filepath.Join(qDir(st), id+".bsq"))
		l = append(l[:i], l[i+1:]...)
		_ = qSave(st, l)
		return dest
	}
	return "ERROR:Ese archivo ya no está en la cuarentena."
}

func QuarantineDelete(st *Store, id string) string {
	l := QuarantineList(st)
	for i, q := range l {
		if q.ID == id {
			if err := os.Remove(filepath.Join(qDir(st), id+".bsq")); err != nil && !os.IsNotExist(err) {
				return "No se pudo borrar: " + err.Error()
			}
			l = append(l[:i], l[i+1:]...)
			_ = qSave(st, l)
			return ""
		}
	}
	return ""
}

// ---------- CISA KEV ↔ programas ----------

var reWord = regexp.MustCompile(`[a-z0-9]+`)

// kevRecent devuelve las entradas de KEV de los últimos días que encajan con el nombre del programa.
func kevRecent(name string, kev []KEVEntry, days int) []KEVEntry {
	n := strings.ToLower(name)
	words := map[string]bool{}
	for _, w := range reWord.FindAllString(n, -1) {
		words[w] = true
	}
	limit := time.Now().AddDate(0, 0, -days).Format("2006-01-02")
	var out []KEVEntry
	for _, k := range kev {
		if k.Added < limit {
			continue
		}
		prod := strings.ToLower(k.Product)
		vend := strings.ToLower(k.Vendor)
		pw := reWord.FindAllString(prod, -1)
		if len(pw) == 0 {
			continue
		}
		all := true
		for _, w := range pw {
			if !words[w] {
				all = false
				break
			}
		}
		// el fabricante también tiene que aparecer, salvo que el producto ya lo incluya
		if all && (strings.Contains(n, vend) || strings.Contains(prod, vend) || vend == "") {
			out = append(out, k)
		}
	}
	return out
}
