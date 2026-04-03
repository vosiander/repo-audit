package external

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/vosiander/repoaudit/internal/scanner"
)

// RunTrivy runs Trivy filesystem scan for CVEs, secrets, and misconfigs
func RunTrivy(root string) *scanner.ScanResult {
	// Check if trivy is available
	if _, err := exec.LookPath("trivy"); err != nil {
		return &scanner.ScanResult{
			Category: "Trivy Scan",
			Severity: "warn",
			Message:  "Trivy not installed — install from https://aquasecurity.github.io/trivy",
			Findings: nil,
		}
	}

	// Run trivy
	cmd := exec.Command("trivy", "fs",
		"--scanners", "vuln,secret,misconfig",
		"--format", "json",
		"--severity", "LOW,MEDIUM,HIGH,CRITICAL",
		"--quiet",
		root,
	)
	output, _ := cmd.Output()

	// Parse output
	var data map[string]interface{}
	if err := json.Unmarshal(output, &data); err != nil {
		return &scanner.ScanResult{
			Category: "Trivy Scan",
			Severity: "warn",
			Message:  "Trivy returned non-JSON output",
			Findings: nil,
		}
	}

	var findings []scanner.Finding

	results, ok := data["Results"].([]interface{})
	if !ok {
		return &scanner.ScanResult{
			Category: "Trivy Scan",
			Severity: "ok",
			Message:  "Trivy: no vulnerabilities, secrets, or misconfigs found",
			Findings: nil,
		}
	}

	for _, r := range results {
		result, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		target, _ := result["Target"].(string)

		// Process vulnerabilities
		if vulns, ok := result["Vulnerabilities"].([]interface{}); ok {
			for _, v := range vulns {
				vuln, ok := v.(map[string]interface{})
				if !ok {
					continue
				}

				vulnID, _ := vuln["VulnerabilityID"].(string)
				pkgName, _ := vuln["PkgName"].(string)
				installedVer, _ := vuln["InstalledVersion"].(string)
				severity, _ := vuln["Severity"].(string)
				title, _ := vuln["Title"].(string)

				if len(title) > 100 {
					title = title[:100]
				}

				findings = append(findings, scanner.Finding{
					File: target,
					Line: 0,
					Text: fmt.Sprintf("%s %s@%s [%s] — %s", vulnID, pkgName, installedVer, severity, title),
				})
			}
		}

		// Process secrets
		if secrets, ok := result["Secrets"].([]interface{}); ok {
			for _, s := range secrets {
				secret, ok := s.(map[string]interface{})
				if !ok {
					continue
				}

				category, _ := secret["Category"].(string)
				title, _ := secret["Title"].(string)
				startLine := 0
				if sl, ok := secret["StartLine"].(float64); ok {
					startLine = int(sl)
				}

				if len(title) > 100 {
					title = title[:100]
				}

				findings = append(findings, scanner.Finding{
					File: target,
					Line: startLine,
					Text: fmt.Sprintf("SECRET: %s — %s", category, title),
				})
			}
		}

		// Process misconfigurations
		if misconfigs, ok := result["Misconfigurations"].([]interface{}); ok {
			for _, m := range misconfigs {
				misconfig, ok := m.(map[string]interface{})
				if !ok {
					continue
				}

				severity, _ := misconfig["Severity"].(string)
				title, _ := misconfig["Title"].(string)

				if len(title) > 100 {
					title = title[:100]
				}

				findings = append(findings, scanner.Finding{
					File: target,
					Line: 0,
					Text: fmt.Sprintf("MISCONFIG [%s]: %s", severity, title),
				})
			}
		}
	}

	if len(findings) > 0 {
		severity := "warn"
		for _, f := range findings {
			if strings.Contains(f.Text, "CRITICAL") ||
				strings.Contains(f.Text, "HIGH") ||
				strings.Contains(f.Text, "SECRET") {
				severity = "danger"
				break
			}
		}

		return &scanner.ScanResult{
			Category: "Trivy Scan",
			Severity: severity,
			Message:  fmt.Sprintf("Trivy: %d finding(s)", len(findings)),
			Findings: findings,
		}
	}

	return &scanner.ScanResult{
		Category: "Trivy Scan",
		Severity: "ok",
		Message:  "Trivy: no vulnerabilities, secrets, or misconfigs found",
		Findings: nil,
	}
}
