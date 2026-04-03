package output

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/vosiander/repoaudit/internal/scanner"
)

var (
	red     = color.New(color.FgRed)
	green   = color.New(color.FgGreen)
	yellow  = color.New(color.FgYellow)
	blue    = color.New(color.FgBlue)
	dim     = color.New(color.Faint)
	bold    = color.New(color.Bold)
	boldRed = color.New(color.Bold, color.FgRed)
)

// Heading prints a section heading
func Heading(title string) {
	fmt.Println()
	color.New(color.Bold, color.FgBlue).Println(strings.Repeat("─", 60))
	color.New(color.Bold, color.FgBlue).Printf("  %s\n", title)
	color.New(color.Bold, color.FgBlue).Println(strings.Repeat("─", 60))
}

// Ok prints a success message
func Ok(msg string) {
	green.Print("  ✔ ")
	fmt.Println(msg)
}

// Warn prints a warning message
func Warn(msg string) {
	yellow.Print("  ⚠ ")
	fmt.Println(msg)
}

// Danger prints a danger message
func Danger(msg string) {
	red.Print("  ✘ ")
	fmt.Println(msg)
}

// Info prints an info message
func Info(msg string) {
	dim.Print("  ℹ ")
	fmt.Println(msg)
}

// Error prints an error message to stderr
func Error(msg string) {
	fmt.Fprintln(os.Stderr, red.Sprint(msg))
}

// Finding prints a finding detail
func Finding(file string, line int, text string) {
	yellow.Print("    → ")
	dim.Printf("%s:%d  ", file, line)
	fmt.Println()

	trimmed := strings.TrimSpace(text)
	if len(trimmed) > 120 {
		trimmed = trimmed[:120]
	}
	dim.Printf("      %s\n", trimmed)
}

// PrintReport prints grouped findings and returns exit code
func PrintReport(results []scanner.ScanResult) int {
	grouped := make(map[string][]scanner.ScanResult)
	for _, r := range results {
		grouped[r.Category] = append(grouped[r.Category], r)
	}

	totalDanger := 0
	totalWarn := 0

	// Print in a consistent order
	categories := []string{
		"Network / Exfiltration",
		"Code Injection",
		"Credential Access",
		"Subprocess / Shell",
		"File I/O",
		"Install Hooks",
		"Dependency CVEs",
		"Trivy Scan",
	}

	for _, category := range categories {
		items, ok := grouped[category]
		if !ok {
			continue
		}

		Heading(category)
		for _, r := range items {
			switch r.Severity {
			case "ok":
				Ok(r.Message)
			case "warn":
				Warn(r.Message)
				totalWarn++
			default:
				Danger(r.Message)
				totalDanger++
			}

			// Print up to 10 findings per check
			for i, f := range r.Findings {
				if i >= 10 {
					Info(fmt.Sprintf("  … and %d more", len(r.Findings)-10))
					break
				}
				Finding(f.File, f.Line, f.Text)
			}
		}
	}

	// Summary
	Heading("SUMMARY")
	if totalDanger > 0 {
		red.Printf("  Dangerous findings: %d\n", totalDanger)
	} else {
		green.Printf("  Dangerous findings: %d\n", totalDanger)
	}
	if totalWarn > 0 {
		yellow.Printf("  Warnings:           %d\n", totalWarn)
	} else {
		green.Printf("  Warnings:           %d\n", totalWarn)
	}

	fmt.Println()
	if totalDanger == 0 && totalWarn == 0 {
		color.New(color.Bold, color.FgGreen).Println("  All clear — no issues detected.")
	} else if totalDanger == 0 {
		color.New(color.Bold, color.FgYellow).Println("  Review warnings above — likely benign but worth checking.")
	} else {
		color.New(color.Bold, color.FgRed).Println("  Dangerous patterns found — review carefully before installing.")
	}

	if totalDanger > 0 {
		return 1
	}
	return 0
}
