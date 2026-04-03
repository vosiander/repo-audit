package scanner

import (
	"os"
	"path/filepath"
	"strings"
)

// CodeExtensions are file extensions to scan
var CodeExtensions = map[string]bool{
	".py": true, ".pyx": true, ".pxd": true, // Python
	".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true, ".jsx": true, // JS/TS
	".sh": true, ".bash": true, ".zsh": true, // Shell
	".rb":   true, // Ruby
	".go":   true, // Go
	".rs":   true, // Rust
	".toml": true, ".cfg": true, ".ini": true, ".yaml": true, ".yml": true, ".json": true, // Config
}

// SkipDirs are directories to skip during scanning
var SkipDirs = map[string]bool{
	".git": true, "__pycache__": true, "node_modules": true, ".venv": true, "venv": true,
	".tox": true, ".eggs": true, "dist": true, "build": true, ".mypy_cache": true, ".ruff_cache": true,
	"htmlcov": true, ".pytest_cache": true,
}

// SpecialFiles are filenames to always scan regardless of extension
var SpecialFiles = map[string]bool{
	"Makefile": true, "Dockerfile": true, "Jenkinsfile": true, "setup.py": true, "setup.cfg": true,
}

// IterSourceFiles returns all source files worth scanning
func IterSourceFiles(root string) ([]string, error) {
	var files []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		// Skip hidden and excluded directories
		if info.IsDir() {
			name := info.Name()
			if SkipDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if file should be scanned
		name := info.Name()
		ext := strings.ToLower(filepath.Ext(path))

		if CodeExtensions[ext] || SpecialFiles[name] {
			files = append(files, path)
		}

		return nil
	})

	return files, err
}
