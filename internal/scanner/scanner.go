package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// RunPatternScan runs all regex checks across source files
func RunPatternScan(root string) []ScanResult {
	// Compile all patterns
	compiled := make([]struct {
		check Check
		regex *regexp.Regexp
	}, 0, len(AllChecks))

	for _, c := range AllChecks {
		re, err := regexp.Compile(c.Pattern)
		if err != nil {
			continue // Skip invalid patterns
		}
		compiled = append(compiled, struct {
			check Check
			regex *regexp.Regexp
		}{c, re})
	}

	// Initialize hits map
	hits := make(map[string][]Finding)
	for _, c := range AllChecks {
		hits[c.ID] = []Finding{}
	}

	// Scan files
	files, err := IterSourceFiles(root)
	if err != nil {
		return nil
	}

	for _, fpath := range files {
		scanFile(root, fpath, compiled, hits)
	}

	// Build results
	var results []ScanResult
	for _, check := range AllChecks {
		h := hits[check.ID]
		if len(h) > 0 {
			results = append(results, ScanResult{
				Category: check.Category,
				Severity: check.Severity,
				Message:  fmt.Sprintf("%s — %d hit(s)", check.Label, len(h)),
				Findings: h,
			})
		} else {
			results = append(results, ScanResult{
				Category: check.Category,
				Severity: "ok",
				Message:  fmt.Sprintf("%s — none found", check.Label),
				Findings: nil,
			})
		}
	}

	return results
}

func scanFile(root, fpath string, compiled []struct {
	check Check
	regex *regexp.Regexp
}, hits map[string][]Finding) {
	file, err := os.Open(fpath)
	if err != nil {
		return
	}
	defer file.Close()

	relPath, _ := filepath.Rel(root, fpath)

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		stripped := strings.TrimLeft(line, " \t")

		// Skip comments
		if strings.HasPrefix(stripped, "#") || strings.HasPrefix(stripped, "//") {
			continue
		}

		for _, c := range compiled {
			if c.regex.MatchString(line) {
				hits[c.check.ID] = append(hits[c.check.ID], Finding{
					File: relPath,
					Line: lineNum,
					Text: line,
				})
			}
		}
	}
}

// CheckSetupPy checks for setup.py with dangerous install-time code
func CheckSetupPy(root string) *ScanResult {
	setupPath := filepath.Join(root, "setup.py")
	if _, err := os.Stat(setupPath); os.IsNotExist(err) {
		return nil
	}

	file, err := os.Open(setupPath)
	if err != nil {
		return nil
	}
	defer file.Close()

	// Compile patterns
	var compiledPatterns []struct {
		regex *regexp.Regexp
		label string
	}
	for _, p := range SetupPyPatterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			continue
		}
		compiledPatterns = append(compiledPatterns, struct {
			regex *regexp.Regexp
			label string
		}{re, p.Label})
	}

	var findings []Finding
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, p := range compiledPatterns {
			if p.regex.MatchString(line) {
				findings = append(findings, Finding{
					File: "setup.py",
					Line: lineNum,
					Text: line,
				})
			}
		}
	}

	if len(findings) > 0 {
		return &ScanResult{
			Category: "Install Hooks",
			Severity: "danger",
			Message:  fmt.Sprintf("setup.py contains %d suspicious pattern(s)", len(findings)),
			Findings: findings,
		}
	}

	return &ScanResult{
		Category: "Install Hooks",
		Severity: "ok",
		Message:  "setup.py looks clean",
		Findings: nil,
	}
}
