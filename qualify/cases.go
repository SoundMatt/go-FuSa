package qualify

// minimalBase contains the file set that satisfies all FUSA001–005 rules.
var minimalBase = map[string]string{
	".fusa.json": `{
  "version": "1",
  "project": {
    "name": "qualify-test",
    "module": "github.com/fusa-qualify/test",
    "standard": "generic"
  },
  "rules": {},
  "report": {"format": "text"}
}`,
	"go.mod":                   "module github.com/fusa-qualify/test\n\ngo 1.22\n",
	"LICENSE":                  "Mozilla Public License 2.0\n",
	"README.md":                "# qualify-test\n",
	".github/workflows/ci.yml": "name: CI\n",
}

// mergeBase returns a copy of minimalBase extended with extra.
func mergeBase(extra map[string]string) map[string]string {
	m := make(map[string]string, len(minimalBase)+len(extra))
	for k, v := range minimalBase {
		m[k] = v
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// builtinCases is the built-in qualification test suite.
// Each rule has one positive case (ExpectFinding: true) and one negative case (ExpectFinding: false).
//
//nolint:lll
var builtinCases = []Case{

	// ── FUSA001: .fusa.json present ──────────────────────────────────────────

	{
		Name:          "FUSA001-pos: missing .fusa.json",
		RuleID:        "FUSA001",
		Description:   "Project without .fusa.json must produce a FUSA001 finding.",
		ExpectFinding: true,
		Files: map[string]string{
			"go.mod":                   "module github.com/fusa-qualify/test\n\ngo 1.22\n",
			"LICENSE":                  "Mozilla Public License 2.0\n",
			"README.md":                "# qualify-test\n",
			".github/workflows/ci.yml": "name: CI\n",
		},
	},
	{
		Name:          "FUSA001-neg: .fusa.json present",
		RuleID:        "FUSA001",
		Description:   "Project with .fusa.json must not produce a FUSA001 finding.",
		ExpectFinding: false,
		Files:         minimalBase,
	},

	// ── FUSA002: go.mod present ───────────────────────────────────────────────

	{
		Name:          "FUSA002-pos: missing go.mod",
		RuleID:        "FUSA002",
		Description:   "Project without go.mod must produce a FUSA002 finding.",
		ExpectFinding: true,
		Files: map[string]string{
			".fusa.json": minimalBase[".fusa.json"],
			"LICENSE":    "MPL 2.0\n",
			"README.md":  "# test\n",
		},
	},
	{
		Name:          "FUSA002-neg: go.mod present",
		RuleID:        "FUSA002",
		Description:   "Project with go.mod must not produce a FUSA002 finding.",
		ExpectFinding: false,
		Files:         minimalBase,
	},

	// ── FUSA003: LICENSE present ──────────────────────────────────────────────

	{
		Name:          "FUSA003-pos: missing LICENSE",
		RuleID:        "FUSA003",
		Description:   "Project without LICENSE must produce a FUSA003 finding.",
		ExpectFinding: true,
		Files: map[string]string{
			".fusa.json": minimalBase[".fusa.json"],
			"go.mod":     minimalBase["go.mod"],
			"README.md":  "# test\n",
		},
	},
	{
		Name:          "FUSA003-neg: LICENSE present",
		RuleID:        "FUSA003",
		Description:   "Project with LICENSE must not produce a FUSA003 finding.",
		ExpectFinding: false,
		Files:         minimalBase,
	},

	// ── FUSA004: README present ───────────────────────────────────────────────

	{
		Name:          "FUSA004-pos: missing README",
		RuleID:        "FUSA004",
		Description:   "Project without README must produce a FUSA004 finding.",
		ExpectFinding: true,
		Files: map[string]string{
			".fusa.json": minimalBase[".fusa.json"],
			"go.mod":     minimalBase["go.mod"],
			"LICENSE":    "MPL 2.0\n",
		},
	},
	{
		Name:          "FUSA004-neg: README.md present",
		RuleID:        "FUSA004",
		Description:   "Project with README.md must not produce a FUSA004 finding.",
		ExpectFinding: false,
		Files:         minimalBase,
	},

	// ── FUSA005: CI config present ────────────────────────────────────────────

	{
		Name:          "FUSA005-pos: missing CI config",
		RuleID:        "FUSA005",
		Description:   "Project without .github/workflows/*.yml must produce a FUSA005 finding.",
		ExpectFinding: true,
		Files: map[string]string{
			".fusa.json": minimalBase[".fusa.json"],
			"go.mod":     minimalBase["go.mod"],
			"LICENSE":    "MPL 2.0\n",
			"README.md":  "# test\n",
		},
	},
	{
		Name:          "FUSA005-neg: CI config present",
		RuleID:        "FUSA005",
		Description:   "Project with a CI workflow must not produce a FUSA005 finding.",
		ExpectFinding: false,
		Files:         minimalBase,
	},

	// ── LINT001: discarded error return ───────────────────────────────────────

	{
		Name:          "LINT001-pos: error return discarded with blank identifier",
		RuleID:        "LINT001",
		Description:   "A multi-return call that uses _ to discard the error must produce LINT001.",
		ExpectFinding: true,
		Files: mergeBase(map[string]string{
			"bad.go": "package main\n\nimport \"os\"\n\nfunc Foo() {\n\tf, _ := os.Open(\"x\")\n\t_ = f\n}\n",
		}),
	},
	{
		Name:          "LINT001-neg: all return values captured",
		RuleID:        "LINT001",
		Description:   "A call that captures all return values must not produce LINT001.",
		ExpectFinding: false,
		Files: mergeBase(map[string]string{
			"ok.go": "package main\n\nimport \"os\"\n\nfunc Foo() error {\n\tf, err := os.Open(\"x\")\n\tif err != nil {\n\t\treturn err\n\t}\n\t_ = f\n\treturn nil\n}\n",
		}),
	},

	// ── LINT002: panic() call ─────────────────────────────────────────────────

	{
		Name:          "LINT002-pos: panic() call present",
		RuleID:        "LINT002",
		Description:   "A file containing panic() must produce a LINT002 finding.",
		ExpectFinding: true,
		Files: mergeBase(map[string]string{
			"bad.go": "package main\n\nfunc Foo() {\n\tpanic(\"not implemented\")\n}\n",
		}),
	},
	{
		Name:          "LINT002-neg: no panic() call",
		RuleID:        "LINT002",
		Description:   "A file with no panic() must not produce a LINT002 finding.",
		ExpectFinding: false,
		Files: mergeBase(map[string]string{
			"ok.go": "package main\n\nfunc Foo() {}\n",
		}),
	},

	// ── LINT003: recover() call ───────────────────────────────────────────────

	{
		Name:          "LINT003-pos: recover() call present",
		RuleID:        "LINT003",
		Description:   "A file using recover() must produce a LINT003 finding.",
		ExpectFinding: true,
		Files: mergeBase(map[string]string{
			"bad.go": "package main\n\nfunc Foo() {\n\tdefer func() { recover() }()\n}\n",
		}),
	},
	{
		Name:          "LINT003-neg: no recover() call",
		RuleID:        "LINT003",
		Description:   "A file with no recover() must not produce a LINT003 finding.",
		ExpectFinding: false,
		Files: mergeBase(map[string]string{
			"ok.go": "package main\n\nfunc Foo() {}\n",
		}),
	},

	// ── LINT004: unsafe import ────────────────────────────────────────────────

	{
		Name:          "LINT004-pos: unsafe import",
		RuleID:        "LINT004",
		Description:   "Importing \"unsafe\" must produce a LINT004 finding.",
		ExpectFinding: true,
		Files: mergeBase(map[string]string{
			"bad.go": "package main\n\nimport \"unsafe\"\n\nvar _ = unsafe.Sizeof(0)\n",
		}),
	},
	{
		Name:          "LINT004-neg: no unsafe import",
		RuleID:        "LINT004",
		Description:   "A file that does not import \"unsafe\" must not produce LINT004.",
		ExpectFinding: false,
		Files: mergeBase(map[string]string{
			"ok.go": "package main\n\nfunc Foo() {}\n",
		}),
	},

	// ── LINT005: reflect import ───────────────────────────────────────────────

	{
		Name:          "LINT005-pos: reflect import",
		RuleID:        "LINT005",
		Description:   "Importing \"reflect\" must produce a LINT005 finding.",
		ExpectFinding: true,
		Files: mergeBase(map[string]string{
			"bad.go": "package main\n\nimport \"reflect\"\n\nfunc Foo(v interface{}) string {\n\treturn reflect.TypeOf(v).String()\n}\n",
		}),
	},
	{
		Name:          "LINT005-neg: no reflect import",
		RuleID:        "LINT005",
		Description:   "A file that does not import \"reflect\" must not produce LINT005.",
		ExpectFinding: false,
		Files: mergeBase(map[string]string{
			"ok.go": "package main\n\nfunc Foo() {}\n",
		}),
	},

	// ── LINT006: global mutable variable ─────────────────────────────────────

	{
		Name:          "LINT006-pos: global mutable var",
		RuleID:        "LINT006",
		Description:   "A package-level mutable var must produce a LINT006 finding.",
		ExpectFinding: true,
		Files: mergeBase(map[string]string{
			"bad.go": "package main\n\nvar GlobalState = \"active\"\n",
		}),
	},
	{
		Name:          "LINT006-neg: no global mutable var",
		RuleID:        "LINT006",
		Description:   "A package with only functions and constants must not produce LINT006.",
		ExpectFinding: false,
		Files: mergeBase(map[string]string{
			"ok.go": "package main\n\nconst Version = \"1.0\"\n\nfunc Foo() {}\n",
		}),
	},

	// ── ANA001: goroutine without termination signal ──────────────────────────

	{
		Name:          "ANA001-pos: goroutine with no termination signal",
		RuleID:        "ANA001",
		Description:   "A goroutine with an infinite loop and no select must produce ANA001.",
		ExpectFinding: true,
		Files: mergeBase(map[string]string{
			"bad.go": "package main\n\nfunc Foo() {\n\tgo func() {\n\t\tfor {\n\t\t}\n\t}()\n}\n",
		}),
	},
	{
		Name:          "ANA001-neg: goroutine with select on stop channel",
		RuleID:        "ANA001",
		Description:   "A goroutine whose loop contains a select must not produce ANA001.",
		ExpectFinding: false,
		Files: mergeBase(map[string]string{
			"ok.go": "package main\n\nfunc Foo(stop chan struct{}) {\n\tgo func() {\n\t\tfor {\n\t\t\tselect {\n\t\t\tcase <-stop:\n\t\t\t\treturn\n\t\t\t}\n\t\t}\n\t}()\n}\n",
		}),
	},

	// ── ANA002: goroutine spawned inside loop ─────────────────────────────────

	{
		Name:          "ANA002-pos: goroutine spawned inside for loop",
		RuleID:        "ANA002",
		Description:   "A go statement inside a for loop must produce ANA002.",
		ExpectFinding: true,
		Files: mergeBase(map[string]string{
			"bad.go": "package main\n\nfunc Foo() {\n\tfor i := 0; i < 10; i++ {\n\t\tgo func() {}()\n\t}\n}\n",
		}),
	},
	{
		Name:          "ANA002-neg: goroutine spawned outside loop",
		RuleID:        "ANA002",
		Description:   "A go statement outside any loop must not produce ANA002.",
		ExpectFinding: false,
		Files: mergeBase(map[string]string{
			"ok.go": "package main\n\nfunc Foo() {\n\tgo func() {}()\n}\n",
		}),
	},

	// ── ANA003: time.Sleep inside goroutine ───────────────────────────────────

	{
		Name:          "ANA003-pos: time.Sleep inside goroutine",
		RuleID:        "ANA003",
		Description:   "A time.Sleep call inside a goroutine must produce ANA003.",
		ExpectFinding: true,
		Files: mergeBase(map[string]string{
			"bad.go": "package main\n\nimport \"time\"\n\nfunc Foo() {\n\tgo func() {\n\t\ttime.Sleep(time.Second)\n\t}()\n}\n",
		}),
	},
	{
		Name:          "ANA003-neg: no time.Sleep in goroutine",
		RuleID:        "ANA003",
		Description:   "A goroutine that does not call time.Sleep must not produce ANA003.",
		ExpectFinding: false,
		Files: mergeBase(map[string]string{
			"ok.go": "package main\n\nfunc Foo(stop chan struct{}) {\n\tgo func() {\n\t\tfor {\n\t\t\tselect {\n\t\t\tcase <-stop:\n\t\t\t\treturn\n\t\t\t}\n\t\t}\n\t}()\n}\n",
		}),
	},

	// ── ANA004: defer inside loop ─────────────────────────────────────────────

	{
		Name:          "ANA004-pos: defer inside for loop",
		RuleID:        "ANA004",
		Description:   "A defer statement inside a for loop must produce ANA004.",
		ExpectFinding: true,
		Files: mergeBase(map[string]string{
			"bad.go": "package main\n\nfunc Foo(ch chan int) {\n\tfor range 5 {\n\t\tdefer close(ch)\n\t}\n}\n",
		}),
	},
	{
		Name:          "ANA004-neg: defer outside loop",
		RuleID:        "ANA004",
		Description:   "A defer statement outside any loop must not produce ANA004.",
		ExpectFinding: false,
		Files: mergeBase(map[string]string{
			"ok.go": "package main\n\nimport \"os\"\n\nfunc Foo(path string) error {\n\tf, err := os.Open(path)\n\tif err != nil {\n\t\treturn err\n\t}\n\tdefer f.Close()\n\treturn nil\n}\n",
		}),
	},

	// ── TRACE001: .fusa-reqs.json present ────────────────────────────────────

	{
		Name:          "TRACE001-pos: .fusa-reqs.json absent",
		RuleID:        "TRACE001",
		Description:   "Project without .fusa-reqs.json must produce a TRACE001 finding.",
		ExpectFinding: true,
		Files:         minimalBase,
	},
	{
		Name:          "TRACE001-neg: .fusa-reqs.json present",
		RuleID:        "TRACE001",
		Description:   "Project with .fusa-reqs.json must not produce a TRACE001 finding.",
		ExpectFinding: false,
		Files: mergeBase(map[string]string{
			".fusa-reqs.json": `{"requirements":[]}`,
		}),
	},

	// ── TRACE002: all requirements traced ────────────────────────────────────

	{
		Name:          "TRACE002-pos: requirement not traced in source",
		RuleID:        "TRACE002",
		Description:   "A requirement in .fusa-reqs.json with no //fusa:req tag must produce TRACE002.",
		ExpectFinding: true,
		Files: mergeBase(map[string]string{
			".fusa-reqs.json": `{"requirements":[{"id":"REQ-001","title":"Safety requirement"}]}`,
		}),
	},
	{
		Name:          "TRACE002-neg: requirement traced in source",
		RuleID:        "TRACE002",
		Description:   "A requirement with a matching //fusa:req tag must not produce TRACE002.",
		ExpectFinding: false,
		Files: mergeBase(map[string]string{
			".fusa-reqs.json": `{"requirements":[{"id":"REQ-001","title":"Safety requirement"}]}`,
			"impl.go":         "package main\n\n//fusa:req REQ-001\nfunc Foo() {}\n",
		}),
	},

	// ── VERIFY001: .fusa-evidence.json present ───────────────────────────────

	{
		Name:          "VERIFY001-pos: .fusa-evidence.json absent",
		RuleID:        "VERIFY001",
		Description:   "Project without .fusa-evidence.json must produce a VERIFY001 finding.",
		ExpectFinding: true,
		Files:         minimalBase,
	},
	{
		Name:          "VERIFY001-neg: .fusa-evidence.json present",
		RuleID:        "VERIFY001",
		Description:   "Project with .fusa-evidence.json must not produce a VERIFY001 finding.",
		ExpectFinding: false,
		Files: mergeBase(map[string]string{
			".fusa-evidence.json": `{"generatedAt":"2026-01-01T00:00:00Z","projectRoot":".","goVersion":"go1.22","results":[],"summary":{"total":0,"passed":0,"failed":0,"skipped":0}}`,
		}),
	},

	// ── VERIFY002: no failed tests in bundle ──────────────────────────────────

	{
		Name:          "VERIFY002-pos: bundle contains failed tests",
		RuleID:        "VERIFY002",
		Description:   "A test evidence bundle with failures must produce a VERIFY002 finding.",
		ExpectFinding: true,
		Files: mergeBase(map[string]string{
			".fusa-evidence.json": `{"generatedAt":"2026-01-01T00:00:00Z","projectRoot":".","goVersion":"go1.22","results":[{"name":"TestFail","package":"pkg","status":"fail","elapsed":0.001}],"summary":{"total":1,"passed":0,"failed":1,"skipped":0}}`,
		}),
	},
	{
		Name:          "VERIFY002-neg: bundle contains only passed tests",
		RuleID:        "VERIFY002",
		Description:   "A test evidence bundle with no failures must not produce VERIFY002.",
		ExpectFinding: false,
		Files: mergeBase(map[string]string{
			".fusa-evidence.json": `{"generatedAt":"2026-01-01T00:00:00Z","projectRoot":".","goVersion":"go1.22","results":[{"name":"TestPass","package":"pkg","status":"pass","elapsed":0.001}],"summary":{"total":1,"passed":1,"failed":0,"skipped":0}}`,
		}),
	},

	// ── RELEASE001: sbom.json present ────────────────────────────────────────

	{
		Name:          "RELEASE001-pos: sbom.json absent",
		RuleID:        "RELEASE001",
		Description:   "Project without sbom.json must produce a RELEASE001 finding.",
		ExpectFinding: true,
		Files:         minimalBase,
	},
	{
		Name:          "RELEASE001-neg: sbom.json present",
		RuleID:        "RELEASE001",
		Description:   "Project with sbom.json must not produce a RELEASE001 finding.",
		ExpectFinding: false,
		Files: mergeBase(map[string]string{
			"sbom.json": `{"spdxVersion":"SPDX-2.3","name":"qualify-test","packages":[]}`,
		}),
	},

	// ── RELEASE002: provenance.json present ──────────────────────────────────

	{
		Name:          "RELEASE002-pos: provenance.json absent",
		RuleID:        "RELEASE002",
		Description:   "Project without provenance.json must produce a RELEASE002 finding.",
		ExpectFinding: true,
		Files:         minimalBase,
	},
	{
		Name:          "RELEASE002-neg: provenance.json present",
		RuleID:        "RELEASE002",
		Description:   "Project with provenance.json must not produce a RELEASE002 finding.",
		ExpectFinding: false,
		Files: mergeBase(map[string]string{
			"provenance.json": `{"buildTimestamp":"2026-01-01T00:00:00Z","module":"github.com/fusa-qualify/test","goVersion":"go1.22","vcs":{"system":"git","commit":"","branch":"","dirty":false}}`,
		}),
	},

	// ── QUALIFY001: qualify-report.json present ───────────────────────────────

	{
		Name:          "QUALIFY001-pos: qualify-report.json absent",
		RuleID:        "QUALIFY001",
		Description:   "Project without qualify-report.json must produce a QUALIFY001 finding.",
		ExpectFinding: true,
		Files:         minimalBase,
	},
	{
		Name:          "QUALIFY001-neg: qualify-report.json present",
		RuleID:        "QUALIFY001",
		Description:   "Project with qualify-report.json must not produce a QUALIFY001 finding.",
		ExpectFinding: false,
		Files: mergeBase(map[string]string{
			"qualify-report.json": `{"generatedAt":"2026-01-01T00:00:00Z","goVersion":"go1.22","module":"github.com/SoundMatt/go-FuSa","total":44,"passed":44,"failed":0,"results":[],"hash":"abc123"}`,
		}),
	},
}
