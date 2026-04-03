package git

import (
	"fmt"
	"os/exec"
	"strings"
)

// IsRemoteURL checks if the target is a remote git URL
func IsRemoteURL(target string) bool {
	return strings.HasPrefix(target, "http://") ||
		strings.HasPrefix(target, "https://") ||
		strings.HasPrefix(target, "git@")
}

// Clone performs a shallow clone of a git repository
func Clone(url, dest string) error {
	fmt.Fprintf(nil, "Cloning %s …\n", url)
	cmd := exec.Command("git", "clone", "--depth", "1", "--quiet", url, dest)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone failed: %s", string(output))
	}
	return nil
}
