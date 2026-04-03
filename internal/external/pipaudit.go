package external

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vosiander/repoaudit/internal/scanner"
)

// findRequirements extracts dependency specs from pyproject.toml or requirements.txt
func findRequirements(root string) ([]string, error) {
	// Try pyproject.toml first
	pyproject := filepath.Join(root, "pyproject.toml")
	if _, err := os.Stat(pyproject); err == nil {
		data, err := os.ReadFile(pyproject)
		if err == nil {
			content := string(data)
			// Simple TOML parsing for dependencies
			if idx := strings.Index(content, "dependencies"); idx >= 0 {
				// Extract array content - this is simplified
				start := strings.Index(content[idx:], "[")
				if start >= 0 {
					end := strings.Index(content[idx+start:], "]")
					if end >= 0 {
						arrayContent := content[idx+start : idx+start+end+1]
						// Parse simple array
						var deps []string
						re := regexp.MustCompile(`"([^"]+)"`)
						matches := re.FindAllStringSubmatch(arrayContent, -1)
						for _, m := range matches {
							if len(m) > 1 {
								deps = append(deps, m[1])
							}
						}
						if len(deps) > 0 {
							return deps, nil
						}
					}
				}
			}
		}
	}

	// Try requirements files
	for _, name := range []string{"requirements.txt", "requirements-dev.txt", "requirements.in"} {
		reqFile := filepath.Join(root, name)
		if _, err := os.Stat(reqFile); err == nil {
			data, err := os.ReadFile(reqFile)
			if err != nil {
				continue
			}
			var deps []string
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					deps = append(deps, line)
				}
			}
			if len(deps) > 0 {
				return deps, nil
			}
		}
	}

	return nil, fmt.Errorf("no dependency file found")
}

// RunPipAudit runs pip-audit against the repo's declared dependencies
func RunPipAudit(root string) *scanner.ScanResult {
	deps, err := findRequirements(root)
	if err != nil {
		return &scanner.ScanResult{
			Category: "Dependency CVEs",
			Severity: "warn",
			Message:  "No dependency file found — skipped pip-audit",
			Findings: nil,
		}
	}

	// Check if pip-audit is available
	if _, err := exec.LookPath("pip-audit"); err != nil {
		return &scanner.ScanResult{
			Category: "Dependency CVEs",
			Severity: "warn",
			Message:  "pip-audit not available — install with: pip install pip-audit",
			Findings: nil,
		}
	}

	// Write temp requirements file
	tmpFile, err := os.CreateTemp("", "repoaudit_reqs_*.txt")
	if err != nil {
		return &scanner.ScanResult{
			Category: "Dependency CVEs",
			Severity: "warn",
			Message:  fmt.Sprintf("Failed to create temp file: %v", err),
			Findings: nil,
		}
	}
	defer os.Remove(tmpFile.Name())

	// Strip extras/markers for basic audit
	markerRe := regexp.MustCompile(`\s*;\s*.*$`)
	for _, d := range deps {
		clean := markerRe.ReplaceAllString(d, "")
		clean = strings.TrimSpace(clean)
		if clean != "" {
			tmpFile.WriteString(clean + "\n")
		}
	}
	tmpFile.Close()

	// Run pip-audit
	cmd := exec.Command("pip-audit", "-r", tmpFile.Name(), "--format", "json", "--progress-spinner", "off")
	output, err := cmd.Output()

	// Parse output
	outputStr := string(output)
	if err == nil && strings.TrimSpace(outputStr) == "" {
		return &scanner.ScanResult{
			Category: "Dependency CVEs",
			Severity: "ok",
			Message:  fmt.Sprintf("pip-audit: no known vulnerabilities in %d deps", len(deps)),
			Findings: nil,
		}
	}

	// Check for "no known vulnerabilities" text
	if strings.Contains(strings.ToLower(outputStr), "no known vulnerabilities") {
		return &scanner.ScanResult{
			Category: "Dependency CVEs",
			Severity: "ok",
			Message:  fmt.Sprintf("pip-audit: no known vulnerabilities in %d deps", len(deps)),
			Findings: nil,
		}
	}

	// Try to parse JSON
	var vulns interface{}
	if err := json.Unmarshal(output, &vulns); err != nil {
		return &scanner.ScanResult{
			Category: "Dependency CVEs",
			Severity: "warn",
			Message:  fmt.Sprintf("pip-audit returned non-JSON output: %.200s", outputStr),
			Findings: nil,
		}
	}

	// Extract vulnerabilities
	var findings []scanner.Finding

	switch v := vulns.(type) {
	case map[string]interface{}:
		if deps, ok := v["dependencies"].([]interface{}); ok {
			findings = extractVulns(deps)
		}
	case []interface{}:
		findings = extractVulns(v)
	}

	if len(findings) > 0 {
		return &scanner.ScanResult{
			Category: "Dependency CVEs",
			Severity: "danger",
			Message:  fmt.Sprintf("pip-audit: %d known CVE(s)", len(findings)),
			Findings: findings,
		}
	}

	return &scanner.ScanResult{
		Category: "Dependency CVEs",
		Severity: "ok",
		Message:  fmt.Sprintf("pip-audit: no known vulnerabilities in %d deps", len(deps)),
		Findings: nil,
	}
}

func extractVulns(deps []interface{}) []scanner.Finding {
	var findings []scanner.Finding

	for _, dep := range deps {
		d, ok := dep.(map[string]interface{})
		if !ok {
			continue
		}

		name, _ := d["name"].(string)
		version, _ := d["version"].(string)

		vulns, ok := d["vulns"].([]interface{})
		if !ok {
			continue
		}

		for _, vuln := range vulns {
			v, ok := vuln.(map[string]interface{})
			if !ok {
				continue
			}

			vulnID, _ := v["id"].(string)
			fixVersions := "n/a"
			if fix, ok := v["fix_versions"].([]interface{}); ok && len(fix) > 0 {
				var fixes []string
				for _, f := range fix {
					if s, ok := f.(string); ok {
						fixes = append(fixes, s)
					}
				}
				fixVersions = strings.Join(fixes, ", ")
			}

			findings = append(findings, scanner.Finding{
				File: "pyproject.toml / requirements.txt",
				Line: 0,
				Text: fmt.Sprintf("%s==%s — %s (fix: %s)", name, version, vulnID, fixVersions),
			})
		}
	}

	return findings
}
