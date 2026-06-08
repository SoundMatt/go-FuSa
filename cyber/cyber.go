// Package cyber provides go-FuSa cybersecurity static analysis rules (v0.14–v0.15).
//
// Rules are mapped to CWE weaknesses, ISO 21434 cybersecurity requirements,
// SEI CERT C-derived patterns adapted for Go, and MISRA-C:2023 directives.
// v0.15 adds gosec-inspired rules (CYBER011–020) and exposes Scan for cross-package use.
//
// Rule catalogue:
//
//	CYBER001  Weak cryptographic hash (MD5/SHA-1)        CWE-327
//	CYBER002  Weak symmetric cipher (DES/3DES/RC4)       CWE-327
//	CYBER003  Insecure random source (math/rand)         CWE-330
//	CYBER004  Unsafe pointer usage (import "unsafe")     CWE-242 / MISRA 11.3
//	CYBER005  Command injection risk (exec with var)     CWE-78
//	CYBER006  Hardcoded credential                       CWE-798
//	CYBER007  TLS certificate verification disabled      CWE-295
//	CYBER008  HTTP server without timeouts               CWE-400
//	CYBER009  Integer narrowing conversion               CWE-190 / MISRA 10.3
//	CYBER010  String concatenation in OS/DB API call     CWE-22 / CWE-89
//	CYBER011  SSRF — URL from variable in HTTP client    CWE-918 (gosec G107)
//	CYBER012  Profiling endpoint exposed (pprof)         gosec G108
//	CYBER013  Zip slip — unsafe archive extraction       CWE-23  (gosec G110)
//	CYBER014  TLS minimum version too low                CWE-326 (gosec G112)
//	CYBER015  SQL injection via fmt.Sprintf              CWE-89  (gosec G202)
//	CYBER016  Permissive directory creation mode         CWE-732 (gosec G301)
//	CYBER017  Permissive file creation mode              CWE-732 (gosec G302)
//	CYBER018  File path derived from HTTP request        CWE-22  (gosec G304)
//	CYBER019  TOCTOU race condition on filesystem        CWE-362
//	CYBER020  Insecure temporary file creation           CWE-377 (gosec G303)
//
// Activate by importing this package for its side effects:
//
//	import _ "github.com/SoundMatt/go-FuSa/cyber"
package cyber

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

func init() {
	engine.Default.MustRegister(&ruleWeakHash{})
	engine.Default.MustRegister(&ruleWeakCipher{})
	engine.Default.MustRegister(&ruleInsecureRandom{})
	engine.Default.MustRegister(&ruleUnsafePointer{})
	engine.Default.MustRegister(&ruleCmdInjection{})
	engine.Default.MustRegister(&ruleHardcodedCredential{})
	engine.Default.MustRegister(&ruleTLSInsecureSkipVerify{})
	engine.Default.MustRegister(&ruleHTTPServerNoTimeout{})
	engine.Default.MustRegister(&ruleIntegerNarrowing{})
	engine.Default.MustRegister(&ruleStringConcatInAPI{})
}

// ─── shared AST helpers ───────────────────────────────────────────────────────

type parsedFile struct {
	file *ast.File
	fset *token.FileSet
}

func parseProject(projectRoot string) ([]parsedFile, error) {
	fset := token.NewFileSet()
	var results []parsedFile
	err := filepath.WalkDir(projectRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == "testdata" || (name != "." && strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if parseErr != nil {
			return nil
		}
		results = append(results, parsedFile{file: f, fset: fset})
		return nil
	})
	return results, err
}

// isNolinted returns true when the source line containing pos has a
// //nolint:RULEID or //fusa:ignore RULEID inline comment.
func isNolinted(pf parsedFile, pos token.Pos, ruleID string) bool {
	position := pf.fset.Position(pos)
	for _, cg := range pf.file.Comments {
		for _, c := range cg.List {
			cp := pf.fset.Position(c.Pos())
			if cp.Line != position.Line {
				continue
			}
			text := c.Text
			// Accept nolint:RULE, nolint:A,RULE,B, fusa:ignore RULE.
			if strings.Contains(text, "nolint:"+ruleID) ||
				strings.Contains(text, ","+ruleID) ||
				strings.Contains(text, "fusa:ignore "+ruleID) {
				return true
			}
		}
	}
	return false
}

func location(fset *token.FileSet, pos token.Pos) fusa.Location {
	p := fset.Position(pos)
	return fusa.Location{File: p.Filename, Line: p.Line, Column: p.Column}
}

// hasImport reports whether the file imports the given path.
func hasImport(file *ast.File, importPath string) (token.Pos, bool) {
	for _, imp := range file.Imports {
		if imp.Path.Value == `"`+importPath+`"` {
			return imp.Pos(), true
		}
	}
	return token.NoPos, false
}

// isIdent reports whether expr is an identifier with the given name.
func isIdent(expr ast.Expr, name string) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == name
}

// isSel reports whether expr is <pkg>.<name>.
func isSel(expr ast.Expr, pkg, name string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	return ok && isIdent(sel.X, pkg) && sel.Sel.Name == name
}

// isStringLit reports whether an expression is a string literal.
func isStringLit(e ast.Expr) bool {
	bl, ok := e.(*ast.BasicLit)
	return ok && bl.Kind == token.STRING
}

// isNonEmptyStringLit returns true and the value when e is a non-empty string literal.
func isNonEmptyStringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	v := strings.Trim(bl.Value, `"`+"`")
	return v, len(v) > 0
}

// credentialKeywords are identifier fragment patterns that suggest secret material.
var credentialKeywords = []string{
	"password", "passwd", "secret", "apikey", "api_key", "apitoken",
	"accesstoken", "access_token", "privatekey", "private_key",
	"authtoken", "auth_token", "clientsecret", "client_secret",
}

// isCredentialName reports whether name (lower-cased) contains a credential keyword.
func isCredentialName(name string) bool {
	lower := strings.ToLower(name)
	for _, kw := range credentialKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// isAddBinExpr reports whether e is a binary + expression (string concatenation).
func isAddBinExpr(e ast.Expr) bool {
	bin, ok := e.(*ast.BinaryExpr)
	return ok && bin.Op == token.ADD
}

// ─── CYBER001: weak cryptographic hash ───────────────────────────────────────

type ruleWeakHash struct{}

func (r *ruleWeakHash) ID() string { return "CYBER001" }
func (r *ruleWeakHash) Description() string {
	return "Import of crypto/md5 or crypto/sha1 — weak hash algorithms must not be used for security purposes (CWE-327, ISO 21434 §8.5)."
}

//fusa:req REQ-CYBER001
func (r *ruleWeakHash) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		for _, path := range []string{"crypto/md5", "crypto/sha1"} {
			if pos, ok := hasImport(pf.file, path); ok {
				findings = append(findings, fusa.Finding{
					RuleID:   r.ID(),
					Severity: fusa.SeverityWarning,
					Message: "import of " + path + " — MD5 and SHA-1 are cryptographically broken" +
						" and must not be used for security-sensitive hashing",
					Location:    location(pf.fset, pos),
					Remediation: "replace with crypto/sha256, crypto/sha512, or golang.org/x/crypto/blake2b",
				})
			}
		}
	}
	return findings, nil
}

// ─── CYBER002: weak symmetric cipher ─────────────────────────────────────────

type ruleWeakCipher struct{}

func (r *ruleWeakCipher) ID() string { return "CYBER002" }
func (r *ruleWeakCipher) Description() string {
	return "Import of crypto/des or crypto/rc4 — DES, 3DES, and RC4 are cryptographically broken (CWE-327, MISRA Dir 4.8)."
}

//fusa:req REQ-CYBER002
func (r *ruleWeakCipher) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		for _, path := range []string{"crypto/des", "crypto/rc4"} {
			if pos, ok := hasImport(pf.file, path); ok {
				findings = append(findings, fusa.Finding{
					RuleID:      r.ID(),
					Severity:    fusa.SeverityWarning,
					Message:     "import of " + path + " — DES, 3DES, and RC4 are broken symmetric ciphers",
					Location:    location(pf.fset, pos),
					Remediation: "use crypto/aes with GCM or ChaCha20-Poly1305 (golang.org/x/crypto/chacha20poly1305)",
				})
			}
		}
	}
	return findings, nil
}

// ─── CYBER003: insecure random source ────────────────────────────────────────

type ruleInsecureRandom struct{}

func (r *ruleInsecureRandom) ID() string { return "CYBER003" }
func (r *ruleInsecureRandom) Description() string {
	return "Import of math/rand — pseudo-random source must not be used for security tokens, keys, or nonces (CWE-330, CERT MSC50-CPP)."
}

//fusa:req REQ-CYBER003
func (r *ruleInsecureRandom) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		for _, path := range []string{"math/rand", "math/rand/v2"} {
			if pos, ok := hasImport(pf.file, path); ok {
				findings = append(findings, fusa.Finding{
					RuleID:      r.ID(),
					Severity:    fusa.SeverityInfo,
					Message:     "import of " + path + " — use crypto/rand for security-sensitive random values",
					Location:    location(pf.fset, pos),
					Remediation: "use crypto/rand.Read or crypto/rand.Int for tokens, nonces, and keys",
				})
			}
		}
	}
	return findings, nil
}

// ─── CYBER004: unsafe pointer usage ──────────────────────────────────────────

type ruleUnsafePointer struct{}

func (r *ruleUnsafePointer) ID() string { return "CYBER004" }
func (r *ruleUnsafePointer) Description() string {
	return "Import of unsafe bypasses Go's type system and memory safety guarantees (CWE-242, MISRA Rule 11.3)."
}

//fusa:req REQ-CYBER004
func (r *ruleUnsafePointer) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		if pos, ok := hasImport(pf.file, "unsafe"); ok {
			findings = append(findings, fusa.Finding{
				RuleID:      r.ID(),
				Severity:    fusa.SeverityWarning,
				Message:     "import of \"unsafe\" bypasses Go type safety and memory safety guarantees",
				Location:    location(pf.fset, pos),
				Remediation: "remove unsafe usage; if required for syscall interop, document the invariant with a //nolint:CYBER004 comment",
			})
		}
	}
	return findings, nil
}

// ─── CYBER005: command injection risk ────────────────────────────────────────

type ruleCmdInjection struct{}

func (r *ruleCmdInjection) ID() string { return "CYBER005" }
func (r *ruleCmdInjection) Description() string {
	return "exec.Command/CommandContext with a non-literal command name — potential OS command injection (CWE-78, Contrast ProcessControl)."
}

//fusa:req REQ-CYBER005
func (r *ruleCmdInjection) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			// exec.Command(name, args...) — name is args[0]
			if isSel(call.Fun, "exec", "Command") && len(call.Args) >= 1 {
				if !isStringLit(call.Args[0]) && !isNolinted(pf, call.Pos(), r.ID()) {
					findings = append(findings, fusa.Finding{
						RuleID:      r.ID(),
						Severity:    fusa.SeverityWarning,
						Message:     "exec.Command called with a non-literal command name — verify the value cannot be influenced by untrusted input",
						Location:    location(pf.fset, call.Pos()),
						Remediation: "use a fixed command name string literal; pass variable data only as arguments, never as the command name",
					})
				}
			}
			// exec.CommandContext(ctx, name, args...) — name is args[1]
			if isSel(call.Fun, "exec", "CommandContext") && len(call.Args) >= 2 {
				if !isStringLit(call.Args[1]) && !isNolinted(pf, call.Pos(), r.ID()) {
					findings = append(findings, fusa.Finding{
						RuleID:      r.ID(),
						Severity:    fusa.SeverityWarning,
						Message:     "exec.CommandContext called with a non-literal command name — verify the value cannot be influenced by untrusted input",
						Location:    location(pf.fset, call.Pos()),
						Remediation: "use a fixed command name string literal; pass variable data only as arguments, never as the command name",
					})
				}
			}
			return true
		})
	}
	return findings, nil
}

// ─── CYBER006: hardcoded credential ──────────────────────────────────────────

type ruleHardcodedCredential struct{}

func (r *ruleHardcodedCredential) ID() string { return "CYBER006" }
func (r *ruleHardcodedCredential) Description() string {
	return "Variable or constant with a credential-suggestive name assigned a non-empty string literal (CWE-798, Contrast HardcodedCryptoKey)."
}

//fusa:req REQ-CYBER006
func (r *ruleHardcodedCredential) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			switch decl := n.(type) {
			case *ast.GenDecl:
				// var / const declarations
				for _, spec := range decl.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, name := range vs.Names {
						if !isCredentialName(name.Name) {
							continue
						}
						if i < len(vs.Values) {
							if val, ok := isNonEmptyStringLit(vs.Values[i]); ok && len(val) >= 4 {
								findings = append(findings, fusa.Finding{
									RuleID:      r.ID(),
									Severity:    fusa.SeverityError,
									Message:     "hardcoded credential: " + name.Name + " is assigned a string literal — secrets must not be embedded in source code",
									Location:    location(pf.fset, name.Pos()),
									Remediation: "load credentials from environment variables, a secrets manager, or a configuration file excluded from version control",
								})
							}
						}
					}
				}
			case *ast.AssignStmt:
				// x = "value" or x := "value"
				for i, lhs := range decl.Lhs {
					ident, ok := lhs.(*ast.Ident)
					if !ok {
						continue
					}
					if !isCredentialName(ident.Name) {
						continue
					}
					if i < len(decl.Rhs) {
						if val, ok := isNonEmptyStringLit(decl.Rhs[i]); ok && len(val) >= 4 {
							findings = append(findings, fusa.Finding{
								RuleID:      r.ID(),
								Severity:    fusa.SeverityError,
								Message:     "hardcoded credential: " + ident.Name + " is assigned a string literal — secrets must not be embedded in source code",
								Location:    location(pf.fset, ident.Pos()),
								Remediation: "load credentials from environment variables, a secrets manager, or a configuration file excluded from version control",
							})
						}
					}
				}
			}
			return true
		})
	}
	return findings, nil
}

// ─── CYBER007: TLS verification disabled ─────────────────────────────────────

type ruleTLSInsecureSkipVerify struct{}

func (r *ruleTLSInsecureSkipVerify) ID() string { return "CYBER007" }
func (r *ruleTLSInsecureSkipVerify) Description() string {
	return "tls.Config{InsecureSkipVerify: true} disables certificate verification, enabling MitM attacks (CWE-295, ISO 21434 §10.4)."
}

//fusa:req REQ-CYBER007
func (r *ruleTLSInsecureSkipVerify) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "InsecureSkipVerify" {
					continue
				}
				val, ok := kv.Value.(*ast.Ident)
				if ok && val.Name == "true" {
					findings = append(findings, fusa.Finding{
						RuleID:      r.ID(),
						Severity:    fusa.SeverityError,
						Message:     "InsecureSkipVerify: true disables TLS certificate verification — enables man-in-the-middle attacks",
						Location:    location(pf.fset, key.Pos()),
						Remediation: "remove InsecureSkipVerify or set it to false; use a proper CA bundle for self-signed certificates",
					})
				}
			}
			return true
		})
	}
	return findings, nil
}

// ─── CYBER008: HTTP server without timeouts ───────────────────────────────────

type ruleHTTPServerNoTimeout struct{}

func (r *ruleHTTPServerNoTimeout) ID() string { return "CYBER008" }
func (r *ruleHTTPServerNoTimeout) Description() string {
	return "http.ListenAndServe uses a default Server with no timeouts, enabling slowloris / resource-exhaustion attacks (CWE-400)."
}

//fusa:req REQ-CYBER008
func (r *ruleHTTPServerNoTimeout) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			// http.ListenAndServe / http.ListenAndServeTLS use a nil *http.Server internally.
			fnName := ""
			if isSel(call.Fun, "http", "ListenAndServe") {
				fnName = "ListenAndServe"
			} else if isSel(call.Fun, "http", "ListenAndServeTLS") {
				fnName = "ListenAndServeTLS"
			}
			if fnName != "" {
				findings = append(findings, fusa.Finding{
					RuleID:      r.ID(),
					Severity:    fusa.SeverityWarning,
					Message:     "http." + fnName + " uses the default http.Server which has no read/write timeouts",
					Location:    location(pf.fset, call.Pos()),
					Remediation: "use &http.Server{ReadTimeout: ..., WriteTimeout: ..., IdleTimeout: ...}.ListenAndServe(addr)",
				})
			}
			return true
		})
	}
	return findings, nil
}

// ─── CYBER009: integer narrowing conversion ───────────────────────────────────

// narrowTypes are numeric types where converting from a wider type can silently
// truncate bits, producing incorrect values (CWE-190, MISRA Rule 10.3).
var narrowTypes = []string{"int8", "int16", "int32", "uint8", "uint16", "uint32", "byte"}

type ruleIntegerNarrowing struct{}

func (r *ruleIntegerNarrowing) ID() string { return "CYBER009" }
func (r *ruleIntegerNarrowing) Description() string {
	return "Explicit narrowing integer conversion (e.g. int32(x)) may silently truncate bits (CWE-190, MISRA Rule 10.3)."
}

//fusa:req REQ-CYBER009
func (r *ruleIntegerNarrowing) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			// Type conversion: the function is an identifier naming a narrow type.
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || len(call.Args) != 1 {
				return true
			}
			isNarrow := false
			for _, t := range narrowTypes {
				if ident.Name == t {
					isNarrow = true
					break
				}
			}
			if !isNarrow {
				return true
			}
			// Allow conversions from literals — those are constant-folded and safe.
			if _, isLit := call.Args[0].(*ast.BasicLit); isLit {
				return true
			}
			findings = append(findings, fusa.Finding{
				RuleID:   r.ID(),
				Severity: fusa.SeverityInfo,
				Message: ident.Name + "(x) — explicit narrowing conversion may silently truncate" +
					" bits if x exceeds the target type's range",
				Location:    location(pf.fset, call.Pos()),
				Remediation: "add an explicit range check before the conversion, or use math/bits or saturating arithmetic",
			})
			return true
		})
	}
	return findings, nil
}

// ─── CYBER010: string concatenation in OS / DB API ───────────────────────────

// osPathFuncs are (package, function) pairs where the first argument is a file path.
var osPathFuncs = [][2]string{
	{"os", "Open"},
	{"os", "OpenFile"},
	{"os", "Create"},
	{"os", "Remove"},
	{"os", "Mkdir"},
	{"os", "MkdirAll"},
	{"os", "ReadFile"},
	{"os", "WriteFile"},
}

// dbQueryFuncs are (receiver-alias, function) pairs where the first argument is an SQL query.
var dbQueryFuncs = [][2]string{
	{"db", "Query"},
	{"db", "QueryRow"},
	{"db", "Exec"},
	{"db", "Prepare"},
}

type ruleStringConcatInAPI struct{}

func (r *ruleStringConcatInAPI) ID() string { return "CYBER010" }
func (r *ruleStringConcatInAPI) Description() string {
	return "String concatenation as argument to OS path or database query function — potential path traversal (CWE-22) or SQL injection (CWE-89)."
}

//fusa:req REQ-CYBER010
func (r *ruleStringConcatInAPI) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			// Check OS path functions.
			for _, pair := range osPathFuncs {
				if pkgIdent.Name == pair[0] && sel.Sel.Name == pair[1] {
					if len(call.Args) >= 1 && isAddBinExpr(call.Args[0]) {
						findings = append(findings, fusa.Finding{
							RuleID:      r.ID(),
							Severity:    fusa.SeverityWarning,
							Message:     pair[0] + "." + pair[1] + " called with string-concatenated path — potential path traversal",
							Location:    location(pf.fset, call.Pos()),
							Remediation: "use filepath.Join and validate the result with filepath.Clean; reject paths containing \"..\"",
						})
					}
					return true
				}
			}
			// Check DB query functions called on any receiver (common variable name "db", "tx").
			for _, pair := range dbQueryFuncs {
				if sel.Sel.Name == pair[1] {
					if len(call.Args) >= 1 && isAddBinExpr(call.Args[0]) {
						findings = append(findings, fusa.Finding{
							RuleID:      r.ID(),
							Severity:    fusa.SeverityWarning,
							Message:     "." + pair[1] + "() called with string-concatenated query — potential SQL injection",
							Location:    location(pf.fset, call.Pos()),
							Remediation: "use parameterised queries: db.Query(\"SELECT ... WHERE id = $1\", id)",
						})
					}
					return true
				}
			}
			return true
		})
	}
	return findings, nil
}

// Scan runs all CYBER rules against projectRoot and returns the findings.
// Other packages (fmea, tara) call this to obtain cyber findings without
// importing the engine directly.
func Scan(ctx context.Context, projectRoot string, cfg *config.Config) ([]fusa.Finding, error) {
	result, err := engine.Default.RunFilter(ctx, projectRoot, cfg, func(r engine.Rule) bool {
		return strings.HasPrefix(r.ID(), "CYBER")
	})
	if err != nil {
		return nil, err
	}
	return result.Findings, nil
}
