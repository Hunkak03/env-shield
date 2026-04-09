package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	runInDir(dir, "git", "add", "hello.go")

	// Change to temp dir for git commands
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	cfg := &Config{
		EntropyThreshold: EntropyThreshold,
		MinSecretLength:  MinSecretLength,
	}

	findings, err := ScanStagedFiles(cfg)
	if err != nil {
		t.Fatalf("ScanStagedFiles error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean file, got %d", len(findings))
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

	runInDir(dir, "git", "add", "config.go")

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	cfg := &Config{
		EntropyThreshold: EntropyThreshold,
		MinSecretLength:  MinSecretLength,
	}

	findings, err := ScanStagedFiles(cfg)
	if err != nil {
		t.Fatalf("ScanStagedFiles error: %v", err)
	}
	if len(findings) < 1 {
		t.Fatalf("expected >= 1 finding for AWS key, got %d", len(findings))
	}
	if findings[0].Type != "AWS Access Key ID" {
		t.Errorf("expected AWS Access Key ID, got %q", findings[0].Type)
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

	runInDir(dir, "git", "add", ".env")

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	cfg := &Config{
		EntropyThreshold: EntropyThreshold,
		MinSecretLength:  MinSecretLength,
	}

	findings, err := ScanStagedFiles(cfg)
	if err != nil {
		t.Fatalf("ScanStagedFiles error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for .env file, got %d", len(findings))
	}
	if findings[0].Layer != "forbidden_file" {
		t.Errorf("expected forbidden_file layer, got %q", findings[0].Layer)
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

	runInDir(dir, "git", "add", "config.go")

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	cfg := &Config{
		EntropyThreshold: EntropyThreshold,
		MinSecretLength:  MinSecretLength,
	}

	findings, err := ScanStagedFiles(cfg)
	if err != nil {
		t.Fatalf("ScanStagedFiles error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for ignored line, got %d", len(findings))
	}
}

func TestIntegration_FormatFindings_Output(t *testing.T) {
	findings := []Finding{
		{File: "config.py", Line: 15, Type: "AWS Access Key ID", Secret: "AKIAIOSFODNN7EXAMPLE", Layer: "regex"},
		{File: ".env", Line: 0, Type: "Forbidden File", Secret: ".env", Layer: "forbidden_file"},
	}

	output := FormatFindings(findings)
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
	output := FormatFindings(nil)
	if output != "" {
		t.Errorf("expected empty string for no findings, got %q", output)
	}
}

// Helper
func runInDir(dir, name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.CombinedOutput()
}

func setupTempRepo(t *testing.T) (dir string, cleanup func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "env-shield-test-*")
	if err != nil {
		t.Fatal(err)
	}

	runGit := func(args ...string) error {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		_, err := cmd.CombinedOutput()
		return err
	}

	_ = runGit("init")
	_ = runGit("config", "user.email", "test@test.com")
	_ = runGit("config", "user.name", "Test")

	return dir, func() { os.RemoveAll(dir) }
}
