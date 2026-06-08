package cyber

// CYBER011–CYBER020: gosec-inspired rules (v0.15)
//
//   CYBER011  SSRF — URL from variable              CWE-918 / gosec G107
//   CYBER012  pprof profiling endpoint exposed      gosec G108
//   CYBER013  Zip slip — unsafe archive extraction  CWE-23  / gosec G110
//   CYBER014  TLS minimum version too low           CWE-326 / gosec G112
//   CYBER015  SQL injection via fmt.Sprintf         CWE-89  / gosec G202
//   CYBER016  Permissive directory creation mode    CWE-732 / gosec G301
//   CYBER017  Permissive file creation mode         CWE-732 / gosec G302
//   CYBER018  File path derived from HTTP request   CWE-22  / gosec G304
//   CYBER019  TOCTOU race on filesystem             CWE-362
//   CYBER020  Insecure temporary file creation      CWE-377 / gosec G303

import (
	"context"
	"go/ast"
	"go/token"
	"strconv"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

func init() {
	engine.Default.MustRegister(&ruleSSRF{})
	engine.Default.MustRegister(&rulePprofExposed{})
	engine.Default.MustRegister(&ruleZipSlip{})
	engine.Default.MustRegister(&ruleTLSMinVersion{})
	engine.Default.MustRegister(&ruleSQLSprintf{})
	engine.Default.MustRegister(&rulePermissiveDir{})
	engine.Default.MustRegister(&rulePermissiveFile{})
	engine.Default.MustRegister(&rulePathFromRequest{})
	engine.Default.MustRegister(&ruleTOCTOU{})
	engine.Default.MustRegister(&ruleInsecureTempFile{})
}

// ─── CYBER011: SSRF ──────────────────────────────────────────────────────────

type ruleSSRF struct{}

func (r *ruleSSRF) ID() string { return "CYBER011" }
func (r *ruleSSRF) Description() string {
	return "CYBER011: HTTP client call with URL from variable — potential SSRF (CWE-918, gosec G107). Validate or whitelist the URL before use."
}

//fusa:req REQ-CYBER011
func (r *ruleSSRF) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	// http functions whose first arg is the URL.
	httpURLFuncs := [][2]string{
		{"http", "Get"}, {"http", "Head"}, {"http", "Post"}, {"http", "PostForm"},
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			// http.Get(url), http.Head(url), etc.
			for _, pair := range httpURLFuncs {
				if isSel(call.Fun, pair[0], pair[1]) && len(call.Args) >= 1 && !isStringLit(call.Args[0]) {
					findings = append(findings, fusa.Finding{
						RuleID:      r.ID(),
						Severity:    fusa.SeverityWarning,
						Message:     "http." + pair[1] + " called with non-literal URL — potential SSRF",
						Location:    location(pf.fset, call.Pos()),
						Remediation: "validate the URL against an allowlist or use a fixed URL",
					})
					return true
				}
			}
			// http.NewRequest(method, url, body) — URL is arg[1]
			if isSel(call.Fun, "http", "NewRequest") && len(call.Args) >= 2 && !isStringLit(call.Args[1]) {
				findings = append(findings, fusa.Finding{
					RuleID:      r.ID(),
					Severity:    fusa.SeverityWarning,
					Message:     "http.NewRequest called with non-literal URL — potential SSRF",
					Location:    location(pf.fset, call.Pos()),
					Remediation: "validate the URL against an allowlist or use a fixed URL",
				})
			}
			return true
		})
	}
	return findings, nil
}

// ─── CYBER012: pprof exposed ─────────────────────────────────────────────────

type rulePprofExposed struct{}

func (r *rulePprofExposed) ID() string { return "CYBER012" }
func (r *rulePprofExposed) Description() string {
	return "CYBER012: net/http/pprof imported — profiling endpoint exposed in production build (gosec G108). Remove before release."
}

//fusa:req REQ-CYBER012
func (r *rulePprofExposed) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		if pos, ok := hasImport(pf.file, "net/http/pprof"); ok {
			findings = append(findings, fusa.Finding{
				RuleID:      r.ID(),
				Severity:    fusa.SeverityWarning,
				Message:     `import "net/http/pprof" registers profiling HTTP endpoints — must not be present in production builds`,
				Location:    location(pf.fset, pos),
				Remediation: "remove the pprof import; enable profiling only in debug builds via a build tag",
			})
		}
	}
	return findings, nil
}

// ─── CYBER013: zip slip ───────────────────────────────────────────────────────

type ruleZipSlip struct{}

func (r *ruleZipSlip) ID() string { return "CYBER013" }
func (r *ruleZipSlip) Description() string {
	return "CYBER013: archive/zip entry Name used in file creation without path sanitisation — potential zip slip (CWE-23, gosec G110)."
}

//fusa:req REQ-CYBER013
func (r *ruleZipSlip) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		if _, ok := hasImport(pf.file, "archive/zip"); !ok {
			continue
		}
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			// os.Create(x.Name) or os.OpenFile(x.Name, ...) or filepath.Join(..., x.Name, ...)
			isFileOp := isSel(call.Fun, "os", "Create") ||
				isSel(call.Fun, "os", "OpenFile") ||
				isSel(call.Fun, "os", "MkdirAll") ||
				isSel(call.Fun, "filepath", "Join")
			if !isFileOp {
				return true
			}
			for _, arg := range call.Args {
				if isDotName(arg) {
					findings = append(findings, fusa.Finding{
						RuleID:      r.ID(),
						Severity:    fusa.SeverityWarning,
						Message:     "zip archive entry Name used in file path operation without sanitisation — potential path traversal",
						Location:    location(pf.fset, call.Pos()),
						Remediation: `sanitise entry names: reject paths containing ".." and ensure result stays within the target directory`,
					})
					return true
				}
			}
			return true
		})
	}
	return findings, nil
}

// isDotName returns true if e is a selector expression ending in ".Name"
// (e.g., f.Name, header.Name — typical zip archive entry field).
func isDotName(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Name"
}

// ─── CYBER014: TLS minimum version ───────────────────────────────────────────

type ruleTLSMinVersion struct{}

func (r *ruleTLSMinVersion) ID() string { return "CYBER014" }
func (r *ruleTLSMinVersion) Description() string {
	return "CYBER014: tls.Config MinVersion set to TLS 1.0 or 1.1 — minimum accepted version is below recommended TLS 1.2 (CWE-326, gosec G112)."
}

// versionTLS10 = 0x0301 = 769; versionTLS11 = 0x0302 = 770.
const (
	versionTLS10 = 769
	versionTLS11 = 770
)

//fusa:req REQ-CYBER014
func (r *ruleTLSMinVersion) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			ident, ok := kv.Key.(*ast.Ident)
			if !ok || ident.Name != "MinVersion" {
				return true
			}
			if isInsecureTLSVersion(kv.Value) {
				findings = append(findings, fusa.Finding{
					RuleID:      r.ID(),
					Severity:    fusa.SeverityWarning,
					Message:     "tls.Config MinVersion set to TLS 1.0 or 1.1 — minimum recommended version is TLS 1.2",
					Location:    location(pf.fset, kv.Pos()),
					Remediation: "set MinVersion: tls.VersionTLS12 or higher",
				})
			}
			return true
		})
	}
	return findings, nil
}

func isInsecureTLSVersion(e ast.Expr) bool {
	// tls.VersionTLS10 or tls.VersionTLS11 selector
	if isSel(e, "tls", "VersionTLS10") || isSel(e, "tls", "VersionTLS11") {
		return true
	}
	// Numeric literal 769 (0x0301) or 770 (0x0302)
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return false
	}
	v, err := strconv.ParseInt(lit.Value, 0, 64)
	return err == nil && (v == versionTLS10 || v == versionTLS11)
}

// ─── CYBER015: SQL injection via fmt.Sprintf ─────────────────────────────────

type ruleSQLSprintf struct{}

func (r *ruleSQLSprintf) ID() string { return "CYBER015" }
func (r *ruleSQLSprintf) Description() string {
	return "CYBER015: Database query built with fmt.Sprintf — potential SQL injection (CWE-89, gosec G202). Use parameterised queries."
}

var dbQueryNames = map[string]bool{
	"Query": true, "QueryRow": true, "QueryContext": true, "QueryRowContext": true,
	"Exec": true, "ExecContext": true, "Prepare": true, "PrepareContext": true,
}

//fusa:req REQ-CYBER015
func (r *ruleSQLSprintf) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
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
			if !ok || !dbQueryNames[sel.Sel.Name] {
				return true
			}
			if len(call.Args) >= 1 && isFmtSprintf(call.Args[0]) {
				findings = append(findings, fusa.Finding{
					RuleID:      r.ID(),
					Severity:    fusa.SeverityWarning,
					Message:     "." + sel.Sel.Name + "() called with fmt.Sprintf query — potential SQL injection",
					Location:    location(pf.fset, call.Pos()),
					Remediation: "use parameterised queries: db.Query(\"SELECT ... WHERE id = $1\", id)",
				})
			}
			return true
		})
	}
	return findings, nil
}

func isFmtSprintf(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	return isSel(call.Fun, "fmt", "Sprintf") || isSel(call.Fun, "fmt", "Fprintf")
}

// ─── CYBER016: permissive directory mode ────────────────────────────────────

type rulePermissiveDir struct{}

func (r *rulePermissiveDir) ID() string { return "CYBER016" }
func (r *rulePermissiveDir) Description() string {
	return "CYBER016: Directory created with mode more permissive than 0750 — world-readable or world-writable (CWE-732, gosec G301)."
}

//fusa:req REQ-CYBER016
func (r *rulePermissiveDir) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
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
			// os.Mkdir(path, mode) or os.MkdirAll(path, mode) — mode is arg[1]
			if (isSel(call.Fun, "os", "Mkdir") || isSel(call.Fun, "os", "MkdirAll")) && len(call.Args) >= 2 {
				if isPermissiveMode(call.Args[1], 0o750) {
					findings = append(findings, fusa.Finding{
						RuleID:      r.ID(),
						Severity:    fusa.SeverityWarning,
						Message:     "directory created with mode more permissive than 0750",
						Location:    location(pf.fset, call.Pos()),
						Remediation: "use mode 0750 (owner+group rwx) or stricter",
					})
				}
			}
			return true
		})
	}
	return findings, nil
}

// ─── CYBER017: permissive file mode ──────────────────────────────────────────

type rulePermissiveFile struct{}

func (r *rulePermissiveFile) ID() string { return "CYBER017" }
func (r *rulePermissiveFile) Description() string {
	return "CYBER017: File created with mode more permissive than 0640 — world-readable or world-writable (CWE-732, gosec G302)."
}

//fusa:req REQ-CYBER017
func (r *rulePermissiveFile) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
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
			// os.OpenFile(path, flags, mode) — mode is arg[2]
			if isSel(call.Fun, "os", "OpenFile") && len(call.Args) >= 3 {
				if isPermissiveMode(call.Args[2], 0o640) {
					findings = append(findings, fusa.Finding{
						RuleID:      r.ID(),
						Severity:    fusa.SeverityWarning,
						Message:     "os.OpenFile called with mode more permissive than 0640",
						Location:    location(pf.fset, call.Pos()),
						Remediation: "use mode 0640 (owner rw, group r) or stricter",
					})
				}
			}
			// os.WriteFile(path, data, mode) — mode is arg[2]
			if isSel(call.Fun, "os", "WriteFile") && len(call.Args) >= 3 {
				if isPermissiveMode(call.Args[2], 0o640) {
					findings = append(findings, fusa.Finding{
						RuleID:      r.ID(),
						Severity:    fusa.SeverityWarning,
						Message:     "os.WriteFile called with mode more permissive than 0640",
						Location:    location(pf.fset, call.Pos()),
						Remediation: "use mode 0640 (owner rw, group r) or stricter",
					})
				}
			}
			return true
		})
	}
	return findings, nil
}

// isPermissiveMode returns true if e is an integer literal with value > threshold.
func isPermissiveMode(e ast.Expr, threshold int64) bool {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return false
	}
	v, err := strconv.ParseInt(lit.Value, 0, 64)
	return err == nil && v > threshold
}

// ─── CYBER018: file path from HTTP request ───────────────────────────────────

type rulePathFromRequest struct{}

func (r *rulePathFromRequest) ID() string { return "CYBER018" }
func (r *rulePathFromRequest) Description() string {
	return "CYBER018: File path derived from HTTP request used in file operation — potential path traversal (CWE-22, gosec G304)."
}

//fusa:req REQ-CYBER018
func (r *rulePathFromRequest) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
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
			// http.ServeFile(w, r, path) — path is arg[2] from request
			if isSel(call.Fun, "http", "ServeFile") && len(call.Args) >= 3 {
				if isRequestDerived(call.Args[2]) {
					findings = append(findings, fusa.Finding{
						RuleID:      r.ID(),
						Severity:    fusa.SeverityWarning,
						Message:     "http.ServeFile path derived from HTTP request — potential path traversal",
						Location:    location(pf.fset, call.Pos()),
						Remediation: "sanitise path with filepath.Clean; ensure it remains within the allowed root",
					})
				}
			}
			// os.Open / os.ReadFile with request-derived path
			for _, fn := range [][2]string{{"os", "Open"}, {"os", "ReadFile"}} {
				if isSel(call.Fun, fn[0], fn[1]) && len(call.Args) >= 1 {
					if isRequestDerived(call.Args[0]) {
						findings = append(findings, fusa.Finding{
							RuleID:      r.ID(),
							Severity:    fusa.SeverityWarning,
							Message:     fn[0] + "." + fn[1] + " path derived from HTTP request — potential path traversal",
							Location:    location(pf.fset, call.Pos()),
							Remediation: "sanitise path with filepath.Clean; ensure it remains within the allowed root",
						})
					}
				}
			}
			return true
		})
	}
	return findings, nil
}

// isRequestDerived returns true if e looks like it came from an HTTP request
// (e.g., r.URL.Path, r.FormValue(...), r.URL.Query().Get(...)).
func isRequestDerived(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		// r.URL.Path — SelectorExpr{X: SelectorExpr{X: r, Sel: URL}, Sel: Path}
		if v.Sel.Name == "Path" || v.Sel.Name == "RawPath" {
			return true
		}
		if inner, ok := v.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "URL" {
			return true
		}
	case *ast.CallExpr:
		// r.FormValue("...") or r.URL.Query().Get("...")
		if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
			if sel.Sel.Name == "FormValue" || sel.Sel.Name == "PostFormValue" {
				return true
			}
			if sel.Sel.Name == "Get" {
				return true
			}
		}
	}
	return false
}

// ─── CYBER019: TOCTOU ────────────────────────────────────────────────────────

type ruleTOCTOU struct{}

func (r *ruleTOCTOU) ID() string { return "CYBER019" }
func (r *ruleTOCTOU) Description() string {
	return "CYBER019: Function calls os.Stat/Lstat then os.Open/Create/Remove — time-of-check/time-of-use race condition (CWE-362)."
}

//fusa:req REQ-CYBER019
func (r *ruleTOCTOU) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			var hasStat, hasOpen bool
			var statPos token.Pos
			ast.Inspect(fn.Body, func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				if isSel(call.Fun, "os", "Stat") || isSel(call.Fun, "os", "Lstat") {
					hasStat = true
					statPos = call.Pos()
				}
				if isSel(call.Fun, "os", "Open") || isSel(call.Fun, "os", "Create") ||
					isSel(call.Fun, "os", "Remove") || isSel(call.Fun, "os", "Rename") ||
					isSel(call.Fun, "os", "OpenFile") {
					hasOpen = true
				}
				return true
			})
			if hasStat && hasOpen {
				findings = append(findings, fusa.Finding{
					RuleID:      r.ID(),
					Severity:    fusa.SeverityWarning,
					Message:     fn.Name.Name + ": os.Stat followed by file operation — TOCTOU race; another process may modify the file between check and use",
					Location:    location(pf.fset, statPos),
					Remediation: "open the file directly and handle ENOENT/EEXIST; avoid stat-then-open patterns",
				})
			}
			return true
		})
	}
	return findings, nil
}

// ─── CYBER020: insecure temp file ────────────────────────────────────────────

type ruleInsecureTempFile struct{}

func (r *ruleInsecureTempFile) ID() string { return "CYBER020" }
func (r *ruleInsecureTempFile) Description() string {
	return "CYBER020: Temporary file created in predictable location — potential symlink attack or race (CWE-377, gosec G303). Use os.CreateTemp."
}

//fusa:req REQ-CYBER020
func (r *ruleInsecureTempFile) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
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
			if !isSel(call.Fun, "os", "Create") && !isSel(call.Fun, "os", "OpenFile") {
				return true
			}
			if len(call.Args) < 1 {
				return true
			}
			if isTempPath(call.Args[0]) {
				findings = append(findings, fusa.Finding{
					RuleID:      r.ID(),
					Severity:    fusa.SeverityWarning,
					Message:     "file created in temp directory with predictable name — use os.CreateTemp for secure temp files",
					Location:    location(pf.fset, call.Pos()),
					Remediation: "replace with os.CreateTemp(\"\", \"prefix-*\") which creates a uniquely-named temp file",
				})
			}
			return true
		})
	}
	return findings, nil
}

// isTempPath returns true if e is a path that clearly targets a temp directory.
func isTempPath(e ast.Expr) bool {
	// String literal containing /tmp
	if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		return containsTmp(lit.Value)
	}
	// filepath.Join(os.TempDir(), ...) or filepath.Join("/tmp", ...)
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	if isSel(call.Fun, "filepath", "Join") && len(call.Args) >= 1 {
		if isTempDirCall(call.Args[0]) {
			return true
		}
		if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			return containsTmp(lit.Value)
		}
	}
	// os.TempDir() + "/" + name
	if isAddBinExpr(e) {
		bin, ok := e.(*ast.BinaryExpr)
		if !ok {
			return false
		}
		if isTempDirCall(bin.X) {
			return true
		}
	}
	return false
}

func isTempDirCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	return ok && isSel(call.Fun, "os", "TempDir")
}

func containsTmp(s string) bool {
	lower := s
	return len(lower) >= 4 && (lower[1:5] == "/tmp" || lower[1:5] == "\\tmp")
}
