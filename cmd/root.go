package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/vosiander/repoaudit/internal/external"
	"github.com/vosiander/repoaudit/internal/git"
	"github.com/vosiander/repoaudit/internal/output"
	"github.com/vosiander/repoaudit/internal/scanner"
)

var (
	skipTrivy    bool
	skipPipAudit bool
	jsonOutput   bool
)

var rootCmd = &cobra.Command{
	Use:   "repoaudit [target]",
	Short: "Audit a Git repo for security risks before installing",
	Long: `repoaudit — Automated security audit for Git repositories.

Checks for:
  1. Network/exfiltration vectors (requests, urllib, socket, etc.)
  2. Code injection risks (eval, exec, compile, base64, obfuscation)
  3. Credential/secret access patterns (.ssh, .aws, .env, API keys)
  4. Subprocess & shell usage
  5. Suspicious file I/O (writes to system paths, /etc, etc.)
  6. Install-time hooks (setup.py cmdclass, post-install scripts)
  7. Dependency CVE scanning via pip-audit
  8. Filesystem scanning via Trivy (if installed)`,
	Example: `  repoaudit https://github.com/user/repo
  repoaudit ./my-local-repo
  repoaudit https://github.com/user/repo --skip-trivy`,
	Args: cobra.ExactArgs(1),
	Run:  runAudit,
}

func init() {
	rootCmd.Flags().BoolVar(&skipTrivy, "skip-trivy", false, "Skip Trivy filesystem scan")
	rootCmd.Flags().BoolVar(&skipPipAudit, "skip-pip-audit", false, "Skip pip-audit dependency CVE scan")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runAudit(cmd *cobra.Command, args []string) {
	target := args[0]
	var repoPath string
	var tmpDir string
	var err error

	// Determine if target is a URL or local path
	if git.IsRemoteURL(target) {
		tmpDir, err = os.MkdirTemp("", "repoaudit_")
		if err != nil {
			output.Error(fmt.Sprintf("Failed to create temp directory: %v", err))
			os.Exit(1)
		}
		defer os.RemoveAll(tmpDir)

		repoPath = filepath.Join(tmpDir, "repo")
		if err := git.Clone(target, repoPath); err != nil {
			output.Error(fmt.Sprintf("Failed to clone %s: %v", target, err))
			os.Exit(1)
		}
	} else {
		repoPath, err = filepath.Abs(target)
		if err != nil {
			output.Error(fmt.Sprintf("Invalid path: %v", err))
			os.Exit(1)
		}
		info, err := os.Stat(repoPath)
		if err != nil || !info.IsDir() {
			output.Error(fmt.Sprintf("Not a directory: %s", target))
			os.Exit(1)
		}
	}

	output.Info(fmt.Sprintf("Auditing: %s", repoPath))

	var results []scanner.ScanResult

	// 1. Pattern scan
	patternResults := scanner.RunPatternScan(repoPath)
	results = append(results, patternResults...)

	// 2. setup.py check
	if setupResult := scanner.CheckSetupPy(repoPath); setupResult != nil {
		results = append(results, *setupResult)
	}

	// 3. pip-audit
	if !skipPipAudit {
		if pipResult := external.RunPipAudit(repoPath); pipResult != nil {
			results = append(results, *pipResult)
		}
	}

	// 4. Trivy
	if !skipTrivy {
		if trivyResult := external.RunTrivy(repoPath); trivyResult != nil {
			results = append(results, *trivyResult)
		}
	}

	if jsonOutput {
		out := make([]map[string]interface{}, len(results))
		for i, r := range results {
			out[i] = map[string]interface{}{
				"category": r.Category,
				"severity": r.Severity,
				"message":  r.Message,
				"findings": r.Findings,
			}
		}
		jsonBytes, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(jsonBytes))
		os.Exit(0)
	}

	exitCode := output.PrintReport(results)
	os.Exit(exitCode)
}
