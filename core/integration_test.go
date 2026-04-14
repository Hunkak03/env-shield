package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ============================================================
// Integration tests — require git installed
// ============================================================

func skipIfNoGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed, skipping integration test")
	}
}

func setupTempGitRepo(t *testing.T) (dir string, cleanup func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "env-shield-test-*")
	if err != nil {
		t.Fatal(err)
	}

	runGit := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, string(out))
		}
	}

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test")

	return dir, func() { os.RemoveAll(dir) }
}

func TestIntegration_ScanStagedFiles_CleanFile(t *testing.T) {
	skipIfNoGit(t)
	dir, cleanup := setupTempGitRepo(t)
	defer cleanup()

	// Create a clean file
	cleanFile := filepath.Join(dir, "hello.go")
	if err := os.WriteFile(cleanFile, []byte(`package main
import "fmt"
func main() {
	fmt.Println("hello world")
}
`), 0644); err != nil {
		t.Fatal(err)
	}

	// Stage it
	runInDir(t, dir, "git", "add", "hello.go")

	// Change to temp dir for git commands
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	cfg := &Config{
		EntropyThreshold: EntropyThreshold,
		MinSecretLength:  MinSecretLength,
		Severity:         SeverityBlock,
	}

	result, err := ScanStagedFiles(cfg)
	if err != nil {
		t.Fatalf("ScanStagedFiles error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for clean file, got %d", len(result.Findings))
	}
}

func TestIntegration_ScanStagedFiles_AWSSecret(t *testing.T) {
	skipIfNoGit(t)
	dir, cleanup := setupTempGitRepo(t)
	defer cleanup()

	// Create file with AWS key
	configFile := filepath.Join(dir, "config.go")
	if err := os.WriteFile(configFile, []byte(`package config
var AWSKey = "AKIAIOSFODNN7EXAMPLE"
`), 0644); err != nil {
		t.Fatal(err)
	}

	runInDir(t, dir, "git", "add", "config.go")

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	cfg := &Config{
		EntropyThreshold: EntropyThreshold,
		MinSecretLength:  MinSecretLength,
		Severity:         SeverityBlock,
	}

	result, err := ScanStagedFiles(cfg)
	if err != nil {
		t.Fatalf("ScanStagedFiles error: %v", err)
	}
	if len(result.Findings) < 1 {
		t.Fatalf("expected >= 1 finding for AWS key, got %d", len(result.Findings))
	}
	if result.Findings[0].Type != "AWS Access Key ID" {
		t.Errorf("expected AWS Access Key ID, got %q", result.Findings[0].Type)
	}
}

func TestIntegration_ScanStagedFiles_ForbiddenFile(t *testing.T) {
	skipIfNoGit(t)
	dir, cleanup := setupTempRepo(t)
	defer cleanup()

	// Create .env file
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("DB_HOST=localhost\n"), 0644); err != nil {
		t.Fatal(err)
	}

	runInDir(t, dir, "git", "add", ".env")

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	cfg := &Config{
		EntropyThreshold: EntropyThreshold,
		MinSecretLength:  MinSecretLength,
		Severity:         SeverityBlock,
	}

	result, err := ScanStagedFiles(cfg)
	if err != nil {
		t.Fatalf("ScanStagedFiles error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding for .env file, got %d", len(result.Findings))
	}
	if result.Findings[0].Layer != "forbidden_file" {
		t.Errorf("expected forbidden_file layer, got %q", result.Findings[0].Layer)
	}
}

func TestIntegration_ScanStagedFiles_IgnoredLine(t *testing.T) {
	skipIfNoGit(t)
	dir, cleanup := setupTempGitRepo(t)
	defer cleanup()

	// Create file with ignored AWS key
	configFile := filepath.Join(dir, "config.go")
	if err := os.WriteFile(configFile, []byte(`package config
var AWSKey = "AKIAIOSFODNN7EXAMPLE" // env-shield-ignore
`), 0644); err != nil {
		t.Fatal(err)
	}

	runInDir(t, dir, "git", "add", "config.go")

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	cfg := &Config{
		EntropyThreshold: EntropyThreshold,
		MinSecretLength:  MinSecretLength,
		Severity:         SeverityBlock,
	}

	result, err := ScanStagedFiles(cfg)
	if err != nil {
		t.Fatalf("ScanStagedFiles error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for ignored line, got %d", len(result.Findings))
	}
}

func TestIntegration_FormatFindings_Output(t *testing.T) {
	result := &ScanResult{
		Findings: []Finding{
			{File: "config.py", Line: 15, Type: "AWS Access Key ID", Secret: "AKIAIOSFODNN7EXAMPLE", Layer: "regex", Severity: SeverityBlock},
			{File: ".env", Line: 0, Type: "Forbidden File", Secret: ".env", Layer: "forbidden_file", Severity: SeverityBlock},
		},
		FilesScanned: 5,
		FilesSkipped: 2,
		Duration:     23 * time.Millisecond,
		BlockedCount: 2,
	}

	output := FormatFindings(result)
	if output == "" {
		t.Fatal("expected non-empty output")
	}

	// Check key elements are present
	expectedParts := []string{
		"SECRETS DETECTED",
		"config.py",
		"Line: 15",
		"AWS Access Key ID",
		"AKIA...MPLE", // Obfuscated
		".env",
		"Forbidden File",
		"env-shield-ignore",
	}
	for _, part := range expectedParts {
		if !strings.Contains(output, part) {
			t.Errorf("expected output to contain %q, got:\n%s", part, output)
		}
	}
}

func TestIntegration_FormatFindings_Empty(t *testing.T) {
	result := &ScanResult{
		FilesScanned: 3,
		Duration:     15 * time.Millisecond,
	}
	output := FormatFindings(result)
	if !strings.Contains(output, "No secrets detected") {
		t.Errorf("expected 'No secrets detected' in output, got:\n%s", output)
	}
	if !strings.Contains(output, "scanned 3 file") {
		t.Errorf("expected file count in output, got:\n%s", output)
	}
}

// Helper
func runInDir(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, string(out))
	}
}

func setupTempRepo(t *testing.T) (dir string, cleanup func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "env-shield-test-*")
	if err != nil {
		t.Fatal(err)
	}

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, string(out))
		}
	}

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test")

	return dir, func() { os.RemoveAll(dir) }
}
