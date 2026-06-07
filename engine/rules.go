// rules.go contains the built-in v0.1 project-structure rules.
// Each rule is registered with Default during package init.

package engine

import (
	"context"
	"os"
	"path/filepath"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
)

func init() {
	Default.MustRegister(&ruleConfigPresent{})
	Default.MustRegister(&ruleGoModPresent{})
	Default.MustRegister(&ruleLicensePresent{})
	Default.MustRegister(&ruleReadmePresent{})
	Default.MustRegister(&ruleCIPresent{})
}

// FUSA001 — .fusa.json must be present.
type ruleConfigPresent struct{}

func (r *ruleConfigPresent) ID() string { return "FUSA001" }
func (r *ruleConfigPresent) Description() string {
	return "Project must have a .fusa.json configuration file."
}

func (r *ruleConfigPresent) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	path := filepath.Join(projectRoot, config.ConfigFile)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return []fusa.Finding{{
				RuleID:      r.ID(),
				Severity:    fusa.SeverityError,
				Message:     "no .fusa.json found in project root",
				Location:    fusa.Location{File: config.ConfigFile},
				Remediation: "run 'gofusa init' to create a starter configuration",
			}}, nil
		}
		return nil, err
	}
	return nil, nil
}

// FUSA002 — go.mod must be present.
type ruleGoModPresent struct{}

func (r *ruleGoModPresent) ID() string { return "FUSA002" }
func (r *ruleGoModPresent) Description() string {
	return "Project must be a Go module (go.mod present)."
}

func (r *ruleGoModPresent) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	path := filepath.Join(projectRoot, "go.mod")
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return []fusa.Finding{{
				RuleID:      r.ID(),
				Severity:    fusa.SeverityError,
				Message:     "no go.mod found — project must be a Go module",
				Location:    fusa.Location{File: "go.mod"},
				Remediation: "run 'go mod init <module-path>' to initialise the module",
			}}, nil
		}
		return nil, err
	}
	return nil, nil
}

// FUSA003 — LICENSE file must be present.
type ruleLicensePresent struct{}

func (r *ruleLicensePresent) ID() string { return "FUSA003" }
func (r *ruleLicensePresent) Description() string {
	return "Project must have a LICENSE file for IP clarity in safety cases."
}

func (r *ruleLicensePresent) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	for _, name := range []string{"LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE"} {
		if _, err := os.Stat(filepath.Join(projectRoot, name)); err == nil {
			return nil, nil
		}
	}
	return []fusa.Finding{{
		RuleID:      r.ID(),
		Severity:    fusa.SeverityWarning,
		Message:     "no LICENSE file found",
		Location:    fusa.Location{File: "LICENSE"},
		Remediation: "add a LICENSE file to clarify IP ownership for assessors",
	}}, nil
}

// FUSA004 — README must be present.
type ruleReadmePresent struct{}

func (r *ruleReadmePresent) ID() string { return "FUSA004" }
func (r *ruleReadmePresent) Description() string {
	return "Project must have a README for assessor orientation."
}

func (r *ruleReadmePresent) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	for _, name := range []string{"README.md", "README.txt", "README"} {
		if _, err := os.Stat(filepath.Join(projectRoot, name)); err == nil {
			return nil, nil
		}
	}
	return []fusa.Finding{{
		RuleID:      r.ID(),
		Severity:    fusa.SeverityWarning,
		Message:     "no README file found",
		Location:    fusa.Location{File: "README.md"},
		Remediation: "add a README.md describing the project's safety context",
	}}, nil
}

// FUSA005 — CI configuration must be present.
type ruleCIPresent struct{}

func (r *ruleCIPresent) ID() string { return "FUSA005" }
func (r *ruleCIPresent) Description() string {
	return "Project must have CI configuration for automated evidence generation."
}

func (r *ruleCIPresent) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	for _, rel := range []string{
		filepath.Join(".github", "workflows"),
		".gitlab-ci.yml",
		"Jenkinsfile",
		".circleci",
		".travis.yml",
		"azure-pipelines.yml",
	} {
		if _, err := os.Stat(filepath.Join(projectRoot, rel)); err == nil {
			return nil, nil
		}
	}
	return []fusa.Finding{{
		RuleID:      r.ID(),
		Severity:    fusa.SeverityWarning,
		Message:     "no CI configuration found",
		Location:    fusa.Location{File: ".github/workflows/"},
		Remediation: "add CI configuration to automate safety evidence generation",
	}}, nil
}
