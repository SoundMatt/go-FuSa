package cyber_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/testutil"

	_ "github.com/SoundMatt/go-FuSa/cyber" // register rules via init
)

// ─── helpers ──────────────────────────────────────────────────────────────────

func runCyber(t *testing.T, src string) []fusa.Finding {
	t.Helper()
	files := testutil.MinimalProject()
	files["pkg/code.go"] = src
	dir := testutil.ProjectDir(t, files)
	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	return result.Findings
}

func hasRule(findings []fusa.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func findingsForRule(findings []fusa.Finding, ruleID string) []fusa.Finding {
	var out []fusa.Finding
	for _, f := range findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

// ─── CYBER001: weak hash ──────────────────────────────────────────────────────

//fusa:test REQ-CYBER001
func TestCYBER001_MD5Import(t *testing.T) {
	findings := runCyber(t, `package pkg
import "crypto/md5"
func HashIt(data []byte) []byte { return md5.New().Sum(data) }
`)
	if !hasRule(findings, "CYBER001") {
		t.Error("CYBER001: expected finding for crypto/md5 import")
	}
}

func TestCYBER001_SHA1Import(t *testing.T) {
	findings := runCyber(t, `package pkg
import "crypto/sha1"
func HashIt(data []byte) []byte { return sha1.New().Sum(data) }
`)
	if !hasRule(findings, "CYBER001") {
		t.Error("CYBER001: expected finding for crypto/sha1 import")
	}
}

func TestCYBER001_SHA256_NoFinding(t *testing.T) {
	findings := runCyber(t, `package pkg
import "crypto/sha256"
func HashIt(data []byte) []byte { h := sha256.New(); return h.Sum(data) }
`)
	if hasRule(findings, "CYBER001") {
		t.Error("CYBER001: unexpected finding for crypto/sha256")
	}
}

func TestCYBER001_Description(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		if r.ID() == "CYBER001" {
			if !strings.Contains(r.Description(), "CWE-327") {
				t.Error("CYBER001: description should reference CWE-327")
			}
			return
		}
	}
	t.Error("CYBER001 not registered")
}

// ─── CYBER002: weak cipher ────────────────────────────────────────────────────

//fusa:test REQ-CYBER002
func TestCYBER002_DES(t *testing.T) {
	findings := runCyber(t, `package pkg
import "crypto/des"
func Encrypt(key []byte) { des.NewCipher(key) }
`)
	if !hasRule(findings, "CYBER002") {
		t.Error("CYBER002: expected finding for crypto/des")
	}
}

func TestCYBER002_RC4(t *testing.T) {
	findings := runCyber(t, `package pkg
import "crypto/rc4"
func Encrypt(key []byte) { rc4.NewCipher(key) }
`)
	if !hasRule(findings, "CYBER002") {
		t.Error("CYBER002: expected finding for crypto/rc4")
	}
}

func TestCYBER002_AES_NoFinding(t *testing.T) {
	findings := runCyber(t, `package pkg
import "crypto/aes"
func Encrypt(key []byte) { aes.NewCipher(key) }
`)
	if hasRule(findings, "CYBER002") {
		t.Error("CYBER002: unexpected finding for crypto/aes")
	}
}

// ─── CYBER003: insecure random ────────────────────────────────────────────────

//fusa:test REQ-CYBER003
func TestCYBER003_MathRand(t *testing.T) {
	findings := runCyber(t, `package pkg
import "math/rand"
func Token() int { return rand.Int() }
`)
	if !hasRule(findings, "CYBER003") {
		t.Error("CYBER003: expected INFO finding for math/rand")
	}
	for _, f := range findingsForRule(findings, "CYBER003") {
		if f.Severity != fusa.SeverityInfo {
			t.Errorf("CYBER003: severity = %s, want INFO", f.Severity)
		}
	}
}

func TestCYBER003_CryptoRand_NoFinding(t *testing.T) {
	findings := runCyber(t, `package pkg
import "crypto/rand"
func Token(b []byte) { rand.Read(b) }
`)
	if hasRule(findings, "CYBER003") {
		t.Error("CYBER003: unexpected finding for crypto/rand")
	}
}

// ─── CYBER004: unsafe pointer ─────────────────────────────────────────────────

//fusa:test REQ-CYBER004
func TestCYBER004_UnsafeImport(t *testing.T) {
	findings := runCyber(t, `package pkg
import "unsafe"
func Size() uintptr { return unsafe.Sizeof(0) }
`)
	if !hasRule(findings, "CYBER004") {
		t.Error("CYBER004: expected finding for import unsafe")
	}
}

func TestCYBER004_NoUnsafe_NoFinding(t *testing.T) {
	findings := runCyber(t, `package pkg
func Safe(x int) int { return x + 1 }
`)
	if hasRule(findings, "CYBER004") {
		t.Error("CYBER004: unexpected finding when unsafe not imported")
	}
}

func TestCYBER004_Description(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		if r.ID() == "CYBER004" {
			if !strings.Contains(r.Description(), "MISRA") {
				t.Error("CYBER004: description should reference MISRA")
			}
			return
		}
	}
	t.Error("CYBER004 not registered")
}

// ─── CYBER005: command injection ──────────────────────────────────────────────

//fusa:test REQ-CYBER005
func TestCYBER005_ExecCommandVariable(t *testing.T) {
	findings := runCyber(t, `package pkg
import "os/exec"
func Run(cmd string) { exec.Command(cmd, "arg") }
`)
	if !hasRule(findings, "CYBER005") {
		t.Error("CYBER005: expected finding for exec.Command with variable name")
	}
}

func TestCYBER005_ExecCommandContextVariable(t *testing.T) {
	findings := runCyber(t, `package pkg
import (
	"context"
	"os/exec"
)
func Run(ctx context.Context, cmd string) { exec.CommandContext(ctx, cmd) }
`)
	if !hasRule(findings, "CYBER005") {
		t.Error("CYBER005: expected finding for exec.CommandContext with variable name")
	}
}

func TestCYBER005_ExecCommandLiteral_NoFinding(t *testing.T) {
	findings := runCyber(t, `package pkg
import "os/exec"
func Run(args []string) { exec.Command("git", args...) }
`)
	if hasRule(findings, "CYBER005") {
		t.Error("CYBER005: unexpected finding for exec.Command with literal name")
	}
}

func TestCYBER005_Severity(t *testing.T) {
	findings := runCyber(t, `package pkg
import "os/exec"
func Run(cmd string) { exec.Command(cmd) }
`)
	for _, f := range findingsForRule(findings, "CYBER005") {
		if f.Severity != fusa.SeverityWarning {
			t.Errorf("CYBER005: severity = %s, want WARNING", f.Severity)
		}
	}
}

// ─── CYBER006: hardcoded credential ──────────────────────────────────────────

//fusa:test REQ-CYBER006
func TestCYBER006_ConstAPIKey(t *testing.T) {
	findings := runCyber(t, `package pkg
const apiKey = "sk-abc1234567890"
`)
	if !hasRule(findings, "CYBER006") {
		t.Error("CYBER006: expected ERROR for const apiKey = \"...\"")
	}
	for _, f := range findingsForRule(findings, "CYBER006") {
		if f.Severity != fusa.SeverityError {
			t.Errorf("CYBER006: severity = %s, want ERROR", f.Severity)
		}
	}
}

func TestCYBER006_VarPassword(t *testing.T) {
	findings := runCyber(t, `package pkg
var password = "hunter2x"
`)
	if !hasRule(findings, "CYBER006") {
		t.Error("CYBER006: expected finding for var password = \"...\"")
	}
}

func TestCYBER006_AssignSecret(t *testing.T) {
	findings := runCyber(t, `package pkg
func f() {
	authToken := "Bearer supersecrettoken"
	_ = authToken
}
`)
	if !hasRule(findings, "CYBER006") {
		t.Error("CYBER006: expected finding for authToken := \"...\"")
	}
}

func TestCYBER006_EmptyString_NoFinding(t *testing.T) {
	findings := runCyber(t, `package pkg
var password = ""
`)
	if hasRule(findings, "CYBER006") {
		t.Error("CYBER006: unexpected finding for empty string")
	}
}

func TestCYBER006_NonCredentialName_NoFinding(t *testing.T) {
	findings := runCyber(t, `package pkg
var username = "alice"
`)
	if hasRule(findings, "CYBER006") {
		t.Error("CYBER006: unexpected finding for non-credential variable name")
	}
}

func TestCYBER006_ShortValue_NoFinding(t *testing.T) {
	// Values of 3 chars or fewer are not flagged (too short to be real secrets).
	findings := runCyber(t, `package pkg
var apiKey = "abc"
`)
	if hasRule(findings, "CYBER006") {
		t.Error("CYBER006: unexpected finding for very short string literal")
	}
}

// ─── CYBER007: TLS verification disabled ──────────────────────────────────────

//fusa:test REQ-CYBER007
func TestCYBER007_InsecureSkipVerifyTrue(t *testing.T) {
	findings := runCyber(t, `package pkg
import "crypto/tls"
func Client() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}
`)
	if !hasRule(findings, "CYBER007") {
		t.Error("CYBER007: expected ERROR for InsecureSkipVerify: true")
	}
	for _, f := range findingsForRule(findings, "CYBER007") {
		if f.Severity != fusa.SeverityError {
			t.Errorf("CYBER007: severity = %s, want ERROR", f.Severity)
		}
	}
}

func TestCYBER007_InsecureSkipVerifyFalse_NoFinding(t *testing.T) {
	findings := runCyber(t, `package pkg
import "crypto/tls"
func Client() *tls.Config {
	return &tls.Config{InsecureSkipVerify: false}
}
`)
	if hasRule(findings, "CYBER007") {
		t.Error("CYBER007: unexpected finding for InsecureSkipVerify: false")
	}
}

func TestCYBER007_Description(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		if r.ID() == "CYBER007" {
			if !strings.Contains(r.Description(), "CWE-295") {
				t.Error("CYBER007: description should reference CWE-295")
			}
			return
		}
	}
	t.Error("CYBER007 not registered")
}

// ─── CYBER008: HTTP server without timeout ────────────────────────────────────

//fusa:test REQ-CYBER008
func TestCYBER008_ListenAndServe(t *testing.T) {
	findings := runCyber(t, `package pkg
import "net/http"
func Serve() { http.ListenAndServe(":8080", nil) }
`)
	if !hasRule(findings, "CYBER008") {
		t.Error("CYBER008: expected finding for http.ListenAndServe")
	}
}

func TestCYBER008_ListenAndServeTLS(t *testing.T) {
	findings := runCyber(t, `package pkg
import "net/http"
func Serve() { http.ListenAndServeTLS(":443", "cert", "key", nil) }
`)
	if !hasRule(findings, "CYBER008") {
		t.Error("CYBER008: expected finding for http.ListenAndServeTLS")
	}
}

func TestCYBER008_CustomServer_NoFinding(t *testing.T) {
	// Using http.Server{} struct directly — rule does not flag this.
	findings := runCyber(t, `package pkg
import (
	"net/http"
	"time"
)
func Serve() {
	srv := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	srv.ListenAndServe()
}
`)
	if hasRule(findings, "CYBER008") {
		t.Error("CYBER008: unexpected finding for custom http.Server")
	}
}

// ─── CYBER009: integer narrowing ──────────────────────────────────────────────

//fusa:test REQ-CYBER009
func TestCYBER009_Int32Variable(t *testing.T) {
	findings := runCyber(t, `package pkg
func f(x int64) int32 { return int32(x) }
`)
	if !hasRule(findings, "CYBER009") {
		t.Error("CYBER009: expected finding for int32(variable)")
	}
	for _, f := range findingsForRule(findings, "CYBER009") {
		if f.Severity != fusa.SeverityInfo {
			t.Errorf("CYBER009: severity = %s, want INFO", f.Severity)
		}
	}
}

func TestCYBER009_Uint8Variable(t *testing.T) {
	findings := runCyber(t, `package pkg
func f(x int) byte { return uint8(x) }
`)
	if !hasRule(findings, "CYBER009") {
		t.Error("CYBER009: expected finding for uint8(variable)")
	}
}

func TestCYBER009_Int32Literal_NoFinding(t *testing.T) {
	findings := runCyber(t, `package pkg
func f() int32 { return int32(42) }
`)
	if hasRule(findings, "CYBER009") {
		t.Error("CYBER009: unexpected finding for int32(literal)")
	}
}

func TestCYBER009_Int64_NoFinding(t *testing.T) {
	// int64 is not a narrowing target.
	findings := runCyber(t, `package pkg
func f(x int) int64 { return int64(x) }
`)
	if hasRule(findings, "CYBER009") {
		t.Error("CYBER009: unexpected finding for int64(variable) — widening")
	}
}

// ─── CYBER010: string concat in OS/DB API ─────────────────────────────────────

//fusa:test REQ-CYBER010
func TestCYBER010_OSOpenConcat(t *testing.T) {
	findings := runCyber(t, `package pkg
import "os"
func Open(base, name string) { os.Open(base + name) }
`)
	if !hasRule(findings, "CYBER010") {
		t.Error("CYBER010: expected finding for os.Open(a+b)")
	}
}

func TestCYBER010_OSOpenLiteral_NoFinding(t *testing.T) {
	findings := runCyber(t, `package pkg
import "os"
func Open() { os.Open("config.json") }
`)
	if hasRule(findings, "CYBER010") {
		t.Error("CYBER010: unexpected finding for os.Open with literal")
	}
}

func TestCYBER010_DBQueryConcat(t *testing.T) {
	findings := runCyber(t, `package pkg
import "database/sql"
func Fetch(db *sql.DB, table string) {
	db.Query("SELECT * FROM " + table)
}
`)
	if !hasRule(findings, "CYBER010") {
		t.Error("CYBER010: expected finding for db.Query with string concatenation")
	}
	for _, f := range findingsForRule(findings, "CYBER010") {
		if f.Severity != fusa.SeverityWarning {
			t.Errorf("CYBER010: severity = %s, want WARNING", f.Severity)
		}
	}
}

func TestCYBER010_DBQueryParameterised_NoFinding(t *testing.T) {
	findings := runCyber(t, `package pkg
import "database/sql"
func Fetch(db *sql.DB, id int) {
	db.Query("SELECT * FROM users WHERE id = $1", id)
}
`)
	if hasRule(findings, "CYBER010") {
		t.Error("CYBER010: unexpected finding for parameterised query")
	}
}

func TestCYBER010_DBExecConcat(t *testing.T) {
	findings := runCyber(t, `package pkg
import "database/sql"
func Del(db *sql.DB, table string) {
	db.Exec("DELETE FROM " + table)
}
`)
	if !hasRule(findings, "CYBER010") {
		t.Error("CYBER010: expected finding for db.Exec with concatenated query")
	}
}

// ─── all rules registered ─────────────────────────────────────────────────────

func TestAllCyberRulesRegistered(t *testing.T) {
	expected := []string{
		"CYBER001", "CYBER002", "CYBER003", "CYBER004", "CYBER005",
		"CYBER006", "CYBER007", "CYBER008", "CYBER009", "CYBER010",
	}
	got := make(map[string]bool)
	for _, r := range engine.Default.Rules() {
		got[r.ID()] = true
	}
	for _, id := range expected {
		if !got[id] {
			t.Errorf("rule %s not registered", id)
		}
	}
}

func TestAllCyberRulesHaveDescriptions(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		if !strings.HasPrefix(r.ID(), "CYBER") {
			continue
		}
		if r.Description() == "" {
			t.Errorf("%s: empty description", r.ID())
		}
	}
}

// ─── engine integration ───────────────────────────────────────────────────────

func TestCyberRules_CleanProject_NoFindings(t *testing.T) {
	// MinimalProject has no dangerous patterns; none of the CYBER rules should fire.
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	for _, f := range result.Findings {
		if strings.HasPrefix(f.RuleID, "CYBER") {
			t.Errorf("unexpected CYBER finding on clean project: %s — %s", f.RuleID, f.Message)
		}
	}
}

// ─── fuzz targets ────────────────────────────────────────────────────────────

func FuzzCyberScan(f *testing.F) {
	f.Add("package pkg\nfunc f() {}\n")
	f.Add("package pkg\nimport \"crypto/md5\"\nfunc f() { md5.New() }\n")
	f.Add("package pkg\nimport \"unsafe\"\nfunc f() uintptr { return unsafe.Sizeof(0) }\n")
	f.Add("package pkg\nconst password = \"supersecret\"\n")
	f.Fuzz(func(t *testing.T, src string) {
		files := testutil.MinimalProject()
		files["fuzz/code.go"] = src
		dir := testutil.ProjectDir(t, files)
		cfg := config.Default("github.com/example/test", "test")
		// Must not panic.
		_, _ = engine.Default.Run(context.Background(), dir, cfg)
	})
}

// ─── report rendering integration ────────────────────────────────────────────

//fusa:test REQ-CYBER010
func TestCYBER010_WriteFile_Concat(t *testing.T) {
	findings := runCyber(t, `package pkg
import "os"
func Write(dir, name string, data []byte) {
	os.WriteFile(dir+"/"+name, data, 0o644)
}
`)
	if !hasRule(findings, "CYBER010") {
		t.Error("CYBER010: expected finding for os.WriteFile(dir+name, ...)")
	}
}

//fusa:test REQ-CYBER005
func TestCYBER005_ExecCommandContextLiteral_NoFinding(t *testing.T) {
	findings := runCyber(t, `package pkg
import (
	"context"
	"os/exec"
)
func Run(ctx context.Context, args []string) {
	exec.CommandContext(ctx, "go", args...)
}
`)
	if hasRule(findings, "CYBER005") {
		t.Error("CYBER005: unexpected finding for exec.CommandContext with literal command")
	}
}

// ─── path/file helpers ────────────────────────────────────────────────────────

// writeSrc creates a temp project with the given Go source file.
func writeSrc(t *testing.T, filename, src string) string {
	t.Helper()
	files := testutil.MinimalProject()
	files[filename] = src
	return testutil.ProjectDir(t, files)
}

//fusa:test REQ-CYBER006
func TestCYBER006_PrivateKey_InFile(t *testing.T) {
	dir := writeSrc(t, "auth/keys.go", `package auth
const privateKey = "-----BEGIN RSA PRIVATE KEY-----"
`)
	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if !hasRule(result.Findings, "CYBER006") {
		t.Error("CYBER006: expected finding for const privateKey = RSA key")
	}
}

//fusa:test REQ-CYBER008
func TestCYBER008_Severity(t *testing.T) {
	findings := runCyber(t, `package pkg
import "net/http"
func s() { http.ListenAndServe(":8080", nil) }
`)
	for _, f := range findingsForRule(findings, "CYBER008") {
		if f.Severity != fusa.SeverityWarning {
			t.Errorf("CYBER008: severity = %s, want WARNING", f.Severity)
		}
	}
}

// ─── snapshot: ensure findings render without error ───────────────────────────

func TestCyberFindings_RenderToBuffer(t *testing.T) {
	findings := runCyber(t, `package pkg
import (
	"crypto/md5"
	"math/rand"
	"os"
	"os/exec"
)
const apiKey = "sk-1234567890abcdef"
func f(cmd, dir, name string) {
	md5.New()
	rand.Int()
	exec.Command(cmd)
	os.Open(dir + name)
}
`)
	var sb strings.Builder
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "CYBER") {
			sb.WriteString(f.RuleID + ": " + f.Message + "\n")
		}
	}
	_ = bytes.NewBufferString(sb.String())

	// Expect findings for at least CYBER001, CYBER003, CYBER005, CYBER006, CYBER010.
	for _, id := range []string{"CYBER001", "CYBER003", "CYBER005", "CYBER006", "CYBER010"} {
		if !hasRule(findings, id) {
			t.Errorf("snapshot: expected %s finding", id)
		}
	}
}

// Make sure os.ReadFile is also checked.
func TestCYBER010_ReadFileConcat(t *testing.T) {
	// We need to avoid importing os twice with the same name in testutil:
	findings := runCyber(t, `package pkg
import "os"
func Read(base, file string) ([]byte, error) {
	return os.ReadFile(base + "/" + file)
}
`)
	if !hasRule(findings, "CYBER010") {
		t.Error("CYBER010: expected finding for os.ReadFile(a+b)")
	}
}

// Inspect file path helper.
func TestWriteSrcHelper(t *testing.T) {
	dir := writeSrc(t, "x/y.go", "package x\n")
	if _, err := os.Stat(filepath.Join(dir, "x/y.go")); err != nil {
		t.Errorf("writeSrc: %v", err)
	}
}
