package cyber_test

// Tests for CYBER011–CYBER020 (gosec-inspired rules, v0.15).

import (
	"testing"
)

// ─── CYBER011: SSRF ──────────────────────────────────────────────────────────

func TestCYBER011_SSRF_Get(t *testing.T) {
	findings := runCyber(t, `package pkg
import "net/http"
func Fetch(url string) (*http.Response, error) { return http.Get(url) }
`)
	if !hasRule(findings, "CYBER011") {
		t.Error("expected CYBER011 for http.Get with variable URL")
	}
}

func TestCYBER011_SSRF_NewRequest(t *testing.T) {
	findings := runCyber(t, `package pkg
import "net/http"
func Fetch(url string) (*http.Request, error) { return http.NewRequest("GET", url, nil) }
`)
	if !hasRule(findings, "CYBER011") {
		t.Error("expected CYBER011 for http.NewRequest with variable URL")
	}
}

func TestCYBER011_SSRF_Negative(t *testing.T) {
	findings := runCyber(t, `package pkg
import "net/http"
func Fetch() (*http.Response, error) { return http.Get("https://api.example.com/data") }
`)
	if hasRule(findings, "CYBER011") {
		t.Error("CYBER011 should not fire for literal URL")
	}
}

// ─── CYBER012: pprof ─────────────────────────────────────────────────────────

func TestCYBER012_Pprof(t *testing.T) {
	findings := runCyber(t, `package pkg
import _ "net/http/pprof"
`)
	if !hasRule(findings, "CYBER012") {
		t.Error("expected CYBER012 for net/http/pprof import")
	}
}

func TestCYBER012_Negative(t *testing.T) {
	findings := runCyber(t, `package pkg
import "net/http"
func Listen() { _ = http.ListenAndServe(":8080", nil) }
`)
	if hasRule(findings, "CYBER012") {
		t.Error("CYBER012 should not fire without pprof import")
	}
}

// ─── CYBER013: zip slip ───────────────────────────────────────────────────────

func TestCYBER013_ZipSlip(t *testing.T) {
	findings := runCyber(t, `package pkg
import (
	"archive/zip"
	"os"
)
func Extract(f *zip.File) error {
	outFile, _ := os.Create(f.Name)
	_ = outFile
	return nil
}
`)
	if !hasRule(findings, "CYBER013") {
		t.Error("expected CYBER013 for os.Create(f.Name) with zip import")
	}
}

func TestCYBER013_Negative(t *testing.T) {
	findings := runCyber(t, `package pkg
import "os"
func Open(name string) *os.File {
	f, _ := os.Open(name)
	return f
}
`)
	if hasRule(findings, "CYBER013") {
		t.Error("CYBER013 should not fire without archive/zip import")
	}
}

// ─── CYBER014: TLS min version ───────────────────────────────────────────────

func TestCYBER014_VersionTLS10(t *testing.T) {
	findings := runCyber(t, `package pkg
import "crypto/tls"
func Config() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS10} }
`)
	if !hasRule(findings, "CYBER014") {
		t.Error("expected CYBER014 for MinVersion: tls.VersionTLS10")
	}
}

func TestCYBER014_VersionTLS11(t *testing.T) {
	findings := runCyber(t, `package pkg
import "crypto/tls"
func Config() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS11} }
`)
	if !hasRule(findings, "CYBER014") {
		t.Error("expected CYBER014 for MinVersion: tls.VersionTLS11")
	}
}

func TestCYBER014_Numeric769(t *testing.T) {
	findings := runCyber(t, `package pkg
import "crypto/tls"
func Config() *tls.Config { return &tls.Config{MinVersion: 769} }
`)
	if !hasRule(findings, "CYBER014") {
		t.Error("expected CYBER014 for MinVersion: 769 (0x0301 = TLS 1.0)")
	}
}

func TestCYBER014_TLS12_Negative(t *testing.T) {
	findings := runCyber(t, `package pkg
import "crypto/tls"
func Config() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }
`)
	if hasRule(findings, "CYBER014") {
		t.Error("CYBER014 should not fire for MinVersion: tls.VersionTLS12")
	}
}

// ─── CYBER015: SQL via fmt.Sprintf ───────────────────────────────────────────

func TestCYBER015_SQLSprintf(t *testing.T) {
	findings := runCyber(t, `package pkg
import (
	"database/sql"
	"fmt"
)
func GetUser(db *sql.DB, id string) {
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
}
`)
	if !hasRule(findings, "CYBER015") {
		t.Error("expected CYBER015 for db.Query(fmt.Sprintf(...))")
	}
}

func TestCYBER015_Negative(t *testing.T) {
	findings := runCyber(t, `package pkg
import "database/sql"
func GetUser(db *sql.DB, id string) {
	db.Query("SELECT * FROM users WHERE id = $1", id)
}
`)
	if hasRule(findings, "CYBER015") {
		t.Error("CYBER015 should not fire for parameterised query")
	}
}

// ─── CYBER016: permissive dir mode ───────────────────────────────────────────

func TestCYBER016_PermissiveDir(t *testing.T) {
	findings := runCyber(t, `package pkg
import "os"
func MakeDir(path string) { os.Mkdir(path, 0777) }
`)
	if !hasRule(findings, "CYBER016") {
		t.Error("expected CYBER016 for os.Mkdir with mode 0777")
	}
}

func TestCYBER016_MkdirAll(t *testing.T) {
	findings := runCyber(t, `package pkg
import "os"
func MakeDir(path string) { os.MkdirAll(path, 0755) }
`)
	if !hasRule(findings, "CYBER016") {
		t.Error("expected CYBER016 for os.MkdirAll with mode 0755")
	}
}

func TestCYBER016_Negative(t *testing.T) {
	findings := runCyber(t, `package pkg
import "os"
func MakeDir(path string) { os.Mkdir(path, 0750) }
`)
	if hasRule(findings, "CYBER016") {
		t.Error("CYBER016 should not fire for mode 0750")
	}
}

// ─── CYBER017: permissive file mode ──────────────────────────────────────────

func TestCYBER017_OpenFile(t *testing.T) {
	findings := runCyber(t, `package pkg
import "os"
func WriteLog(path string) { os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0666) }
`)
	if !hasRule(findings, "CYBER017") {
		t.Error("expected CYBER017 for os.OpenFile with mode 0666")
	}
}

func TestCYBER017_WriteFile(t *testing.T) {
	findings := runCyber(t, `package pkg
import "os"
func Write(path string, data []byte) { os.WriteFile(path, data, 0644) }
`)
	if !hasRule(findings, "CYBER017") {
		t.Error("expected CYBER017 for os.WriteFile with mode 0644")
	}
}

func TestCYBER017_Negative(t *testing.T) {
	findings := runCyber(t, `package pkg
import "os"
func Write(path string, data []byte) { os.WriteFile(path, data, 0600) }
`)
	if hasRule(findings, "CYBER017") {
		t.Error("CYBER017 should not fire for mode 0600")
	}
}

// ─── CYBER018: path from request ─────────────────────────────────────────────

func TestCYBER018_ServeFile(t *testing.T) {
	findings := runCyber(t, `package pkg
import "net/http"
func Handler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, r.URL.Path)
}
`)
	if !hasRule(findings, "CYBER018") {
		t.Error("expected CYBER018 for http.ServeFile with r.URL.Path")
	}
}

func TestCYBER018_Negative(t *testing.T) {
	findings := runCyber(t, `package pkg
import "net/http"
func Handler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "/var/www/static/index.html")
}
`)
	if hasRule(findings, "CYBER018") {
		t.Error("CYBER018 should not fire for literal path")
	}
}

// ─── CYBER019: TOCTOU ────────────────────────────────────────────────────────

func TestCYBER019_TOCTOU(t *testing.T) {
	findings := runCyber(t, `package pkg
import "os"
func Process(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	f, _ := os.Open(path)
	_ = f
	return nil
}
`)
	if !hasRule(findings, "CYBER019") {
		t.Error("expected CYBER019 for os.Stat followed by os.Open in same function")
	}
}

func TestCYBER019_Negative(t *testing.T) {
	findings := runCyber(t, `package pkg
import "os"
func Process(path string) (*os.File, error) {
	return os.Open(path)
}
`)
	if hasRule(findings, "CYBER019") {
		t.Error("CYBER019 should not fire for os.Open without prior os.Stat")
	}
}

// ─── CYBER020: insecure temp file ────────────────────────────────────────────

func TestCYBER020_TempCreate(t *testing.T) {
	findings := runCyber(t, `package pkg
import (
	"os"
	"path/filepath"
)
func WriteTmp() {
	f, _ := os.Create(filepath.Join(os.TempDir(), "myapp.tmp"))
	_ = f
}
`)
	if !hasRule(findings, "CYBER020") {
		t.Error("expected CYBER020 for os.Create in temp directory")
	}
}

func TestCYBER020_Negative(t *testing.T) {
	findings := runCyber(t, `package pkg
import "os"
func WriteTmp() {
	f, _ := os.CreateTemp("", "myapp-*")
	_ = f
}
`)
	if hasRule(findings, "CYBER020") {
		t.Error("CYBER020 should not fire for os.CreateTemp")
	}
}
