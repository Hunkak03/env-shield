package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hunkak03/env-shield/core"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "install":
		cmdInstall()
	case "scan":
		cmdScan()
	case "init":
		cmdInit()
	case "version", "--version", "-v":
		fmt.Printf("Env-Shield v%s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func cmdInstall() {
	if err := core.EnsureGitInstalled(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
		os.Exit(1)
	}

	if err := core.InstallHook(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
		os.Exit(1)
	}
}

func cmdScan() {
	// Find repo root and load config
	repoRoot, err := core.GetRepoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
		os.Exit(1)
	}

	cfg, err := core.LoadConfig(repoRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Warning: could not load config: %v\n", err)
		cfg = &core.Config{
			EntropyThreshold: core.EntropyThreshold,
			MinSecretLength:  core.MinSecretLength,
			Severity:         core.SeverityBlock,
		}
	}

	// Run scan
	result, err := core.ScanStagedFiles(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Scan error: %v\n", err)
		os.Exit(1)
	}

	// Print findings once (handles both empty and populated cases)
	fmt.Print(core.FormatFindings(result))

	// Block commit only if blocking findings exist
	if result.BlockedCount > 0 {
		os.Exit(1)
	}

	// WarnedCount > 0 or no findings: allow commit
	os.Exit(0)
}

func cmdInit() {
	if err := core.InitConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	execName := filepath.Base(os.Args[0])
	fmt.Printf(`Env-Shield v%s — Git pre-commit hook to block credential leaks

Usage:
  %s <command>

Commands:
  install    Install Env-Shield as a pre-commit hook
  scan       Scan staged files for secrets (used by hook)
  init       Create default .env-shield.json config file
  version    Show version information
  help       Show this help message

Examples:
  %s install              # Install the git hook
  %s scan                 # Scan currently staged files
  %s init                 # Generate config file

Detection Layers:
  1. Regex patterns    — AWS, Stripe, Google, GitHub, Slack, Private Keys, JWTs
  2. Shannon entropy   — High-randomness generic tokens
  3. Forbidden files   — .env, .pem, .key, id_rsa, etc.

Config:
  Create .env-shield.json to customize detection thresholds,
  ignored files, and ignored patterns.

Bypass:
  Add "// env-shield-ignore" comment to skip a specific line.
`, version, execName, execName, execName, execName)
}
