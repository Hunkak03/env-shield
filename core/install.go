package core

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// InstallHook installs the Env-Shield pre-commit hook into the current repo.
func InstallHook() error {
	// Find .git directory
	gitDir, err := RunGitCommand("rev-parse", "--git-dir")
	if err != nil {
		return fmt.Errorf("not a git repository: run 'git init' first")
	}
	gitDir = filepath.Clean(filepath.FromSlash(strings.TrimSpace(gitDir)))

	hooksDir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("creating hooks directory: %w", err)
	}

	// Determine the executable path
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("determining executable path: %w", err)
	}
	execPath, err = filepath.Abs(execPath)
	if err != nil {
		return fmt.Errorf("resolving absolute path: %w", err)
	}

	var hookContent string
	var hookPath string
	if runtime.GOOS == "windows" {
		// Windows: use #!/bin/sh shebang (Git Bash handles execution)
		hookPath = filepath.Join(hooksDir, "pre-commit")
		// Use forward slashes for git-bash compatibility
		execPathForward := filepath.ToSlash(execPath)
		hookContent = fmt.Sprintf(`#!/bin/sh
# Env-Shield Pre-Commit Hook (auto-generated)
"%s" scan
rc=$?
if [ $rc -ne 0 ]; then
  exit 1
fi
exit 0
`, execPathForward)
	} else {
		// Unix shell hook
		hookPath = filepath.Join(hooksDir, "pre-commit")
		hookContent = fmt.Sprintf(`#!/bin/sh
# Env-Shield Pre-Commit Hook (auto-generated)
"%s" scan
exit_code=$?
if [ $exit_code -ne 0 ]; then
    exit 1
fi
exit 0
`, execPath)
	}

	// Atomic backup of existing hook
	if _, err := os.Stat(hookPath); err == nil {
		backupPath := hookPath + ".env-shield.bak"
		// Avoid overwriting previous backups
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			if err := copyFile(hookPath, backupPath); err != nil {
				fmt.Fprintf(os.Stderr, "⚠️  Warning: could not backup existing hook: %v\n", err)
			} else {
				fmt.Printf("   📦 Backed up existing hook → %s\n", backupPath)
			}
		}
	}

	if err := os.WriteFile(hookPath, []byte(hookContent), 0755); err != nil {
		return fmt.Errorf("writing hook file: %w", err)
	}

	// On Windows, set core.hooksPath so git can find the hook
	// Only override if not already set — avoid breaking user's existing hooks
	if runtime.GOOS == "windows" {
		existingPath, _ := RunGitCommand("config", "--get", "core.hooksPath")
		if strings.TrimSpace(existingPath) == "" {
			hooksPath := strings.ReplaceAll(hooksDir, "\\", "/")
			if _, err := RunGitCommand("config", "core.hooksPath", hooksPath); err != nil {
				fmt.Fprintf(os.Stderr, "⚠️  Warning: could not set core.hooksPath: %v\n", err)
			}
		}
	}

	fmt.Println("✅ Env-Shield installed successfully!")
	fmt.Printf("   Hook: %s\n", hookPath)
	fmt.Printf("   Config: Create .env-shield.json in your repo root to customize.\n")
	return nil
}

// InitConfig creates a default .env-shield.json config file in the repo root.
func InitConfig() error {
	repoRoot, err := GetRepoRoot()
	if err != nil {
		return fmt.Errorf("not a git repository: run 'git init' first")
	}

	configPath := filepath.Join(repoRoot, ConfigFilename)
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("⚠️  Config file %s already exists.\n", configPath)
		return nil
	}

	cfg := map[string]interface{}{
		"ignore_files":      []string{},
		"ignore_patterns":   []string{`\.test\.`, `\.spec\.`, `test_`, `_test\.`},
		"entropy_threshold": EntropyThreshold,
		"min_secret_length": MinSecretLength,
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}

	fmt.Printf("✅ Created default %s\n", configPath)
	return nil
}

// GetRepoRoot returns the absolute path to the repository root.
func GetRepoRoot() (string, error) {
	out, err := RunGitCommand("rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("getting repo root: %w", err)
	}
	return filepath.Clean(filepath.FromSlash(strings.TrimSpace(out))), nil
}

// EnsureGitInstalled checks that git is available.
func EnsureGitInstalled() error {
	cmd := exec.Command("git", "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git is not installed or not in PATH")
	}
	return nil
}

// copyFile copies a file from src to dst — used for hook backups.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0755)
}
