# 🛡️ Env-Shield

> A high-performance **Git pre-commit hook** written in **Go** that blocks credential leaks before they reach your repository. Built with concurrent execution, constant memory scanning, and zero external dependencies.

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/Hunkak03/env-shield/actions)
[![Coverage](https://img.shields.io/badge/coverage-64.2%25-yellow)](https://github.com/Hunkak03/env-shield)
[![GitHub Stars](https://img.shields.io/github/stars/Hunkak03/env-shield?style=social)](https://github.com/Hunkak03/env-shield)

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Detection Layers](#detection-layers)
- [Configuration](#configuration)
- [Bypass Options](#bypass-options)
- [Performance](#performance)
- [Languages & Tools](#languages--tools)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Author](#author)

---

## Features

- **Three-layer detection** — Regex signatures, Shannon entropy analysis, and forbidden file blocking
- **Concurrent worker pool** — Parallel file analysis with configurable workers
- **Constant O(1) memory** — Streams files line-by-line; never loads entire files into RAM
- **Binary file detection** — Skips images, executables, and lock files via magic numbers and extensions
- **Zero external dependencies** — Built entirely with the Go standard library
- **Configurable severity levels** — `"block"` (blocks commit) or `"warn"` (allows commit with warnings)
- **Custom regex patterns** — Add your organization's proprietary secret formats
- **Atomic hook backup** — Automatically backs up existing hooks before installation
- **Cross-platform** — Works on Windows, Linux, and macOS

---

## Requirements

| Dependency | Version | Purpose |
|------------|---------|---------|
| **Go** | 1.22+ | Compile and run the binary |
| **Git** | 2.0+ | Access staged files and install hooks |

> **Zero external dependencies.** Env-Shield uses only the Go standard library: `bufio`, `regexp`, `math`, `os/exec`, `sync`, and `encoding/json`.

---

## Installation

### Step 1: Install Go

If you don't have Go installed, follow the official guide: https://go.dev/dl/

**Windows:**
```cmd
:: Using winget (Windows 11 / Windows 10 with winget)
winget install GoLang.Go

:: Using Chocolatey
choco install golang

:: Using Scoop
scoop install go
```
After installing, **restart your terminal** (CMD, PowerShell, or Windows Terminal) so the PATH updates.

**Linux:**
```bash
# Debian / Ubuntu
sudo apt update && sudo apt install golang-go

# Fedora / RHEL
sudo dnf install golang

# Arch Linux
sudo pacman -S go
```

**macOS:**
```bash
# Using Homebrew
brew install go

# Using MacPorts
sudo port install go
```

Verify your installation:
```bash
go version
```
> **Note:** You need Go **1.22** or later.

---

### Step 2: Clone and Build

```bash
git clone https://github.com/Hunkak03/env-shield.git
cd env-shield
go build -o env-shield .
```

This produces a binary named:
- **Windows:** `env-shield.exe`
- **Linux / macOS:** `env-shield`

> **Windows PowerShell users:** If you get an execution policy error, run the binary explicitly:
> ```powershell
> .\env-shield.exe install
> ```

---

### Step 3: Install the Pre-Commit Hook

Navigate to **any** Git repository and run:

```bash
cd /path/to/your-repo
<path-to-binary>/env-shield install
```

**Examples per platform:**

| Platform | Example command |
|----------|-----------------|
| **Windows CMD / PowerShell** | `.\env-shield.exe install` |
| **Linux / macOS** | `./env-shield install` |
| **From anywhere on your system** | `/full/path/to/env-shield install` |

This automatically creates `.git/hooks/pre-commit` and configures Git. You only need to do this **once per repository**.

> **⚠️ Windows note:** Env-Shield automatically sets `core.hooksPath` to `.git/hooks` **only if it isn't already set**. If you already have a custom hooks path configured, Env-Shield will respect it and won't overwrite it.

> **Git Bash on Windows:** The hook uses `#!/bin/sh` shebang and works out-of-the-box with Git Bash. No extra configuration needed.

---

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `env-shield install` | Install the pre-commit hook in the current repository |
| `env-shield scan` | Scan currently staged files for secrets |
| `env-shield init` | Generate a default `.env-shield.json` configuration file |
| `env-shield version` | Display version information |
| `env-shield help` | Show help and usage |

### How to Run

**1. Install the hook (once per repo):**

```bash
cd your-repo
env-shield install
```

**2. Work normally — the hook runs automatically on every `git commit`:**

```bash
git add config.py
git commit -m "add configuration"
```

Env-Shield intercepts the commit, scans staged files, and either **allows** or **blocks** the commit based on what it finds.

**3. Run a manual scan anytime (without committing):**

```bash
env-shield scan
```

This scans whatever is currently staged without requiring a commit.

### How to Run — Platform-Specific Examples

**Windows CMD:**
```cmd
cd C:\Projects\my-app
..\env-shield\env-shield.exe install
```

**Windows PowerShell:**
```powershell
Set-Location C:\Projects\my-app
.\env-shield.exe install
```

**Windows Git Bash:**
```bash
cd /c/Projects/my-app
./env-shield.exe install
```

**Linux / macOS:**
```bash
cd ~/Projects/my-app
./env-shield install
```

**Running from anywhere (full path):**
```bash
# Linux / macOS
/home/user/bin/env-shield install

# Windows CMD
C:\tools\env-shield\env-shield.exe install

# Windows PowerShell
C:\tools\env-shield\env-shield.exe install
```

### Typical Workflow

```bash
# 1. Install the hook (once per repository)
env-shield install

# 2. Work normally — stage and commit files
git add config.go
git commit -m "add configuration"

# ← Env-Shield automatically intercepts and scans staged files.
#   If secrets are detected, the commit is blocked with a detailed report.
```

### Example Output — Blocked Commit

```
============================================================
  🛡️  Env-Shield: SECRETS DETECTED!
============================================================
  Found 2 potential secret(s) in 5 staged file(s).
  🚫 2 finding(s) BLOCK commit.
  ⏱️  Scan time: 23ms | Files skipped (binary/ignored): 3
============================================================

  [1] File: config/settings.go
      Line: 15
      Type: AWS Access Key ID
      Layer: regex
      Severity: block
      Value: AKIA...MPLE

  [2] File: .env
      Line: N/A
      Type: Forbidden File
      Layer: forbidden_file
      Severity: block
      Value: .env

============================================================
  💡 To bypass, add "// env-shield-ignore" to the line
     or add the file to ".env-shield.json" ignore list.
============================================================
```

### Example Output — Clean Scan

```
✅ Env-Shield: No secrets detected. (scanned 5 files in 23ms)
```

---

## Detection Layers

### Layer 1 — Regex Signatures (Known Patterns)

16 precompiled patterns that detect provider-specific secrets:

| Provider | Pattern | Example |
|----------|---------|---------|
| **AWS Access Key** | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| **AWS Secret Key** | Contextual assignment | `aws_secret_access_key = wJalr...` |
| **Stripe** | `sk_live_`, `rk_live_`, `pk_live_` | `sk_live_abc123...` |
| **Google API Key** | `AIza...` | `AIzaSyA1B2C3D4...` |
| **Google OAuth** | `ya29....` | `ya29.a0AfH...` |
| **GitHub PAT** | `ghp_...` | `ghp_ABCDEF...` |
| **GitHub OAuth** | `gho_...` | `gho_ABCDEF...` |
| **GitHub Fine-Grained PAT** | `github_pat_...` | `github_pat_11A...` |
| **Slack Bot Token** | `xoxb-...` | `xoxb-12345...` |
| **Slack User Token** | `xoxp-...` | `xoxp-12345...` |
| **Private Keys** | `-----BEGIN ... PRIVATE KEY-----` | PEM/EC/DSA/RSA headers |
| **JWT Tokens** | `eyJ....` | `eyJhbGciOi...` |
| **Database URIs** | `mongodb://`, `postgres://`, `mysql://`, `redis://` | Connection strings |
| **Generic API Key** | `api_key = "..."`, `token = "..."` | Variable assignments |

### Layer 2 — Shannon Entropy Analysis

Identifies high-entropy strings (entropy ≥ 4.5) in variable assignments. Detects generic tokens that don't match any fixed pattern.

```python
# Detected by high entropy even without a known pattern
TOKEN = "xK9mP2vLqR7nW4jTsY8aB3cD5eFgH"
# Entropy: 4.72 → DETECTED
```

### Layer 3 — Forbidden File Blocking

Blocks files by name or extension:

| Category | Files |
|----------|-------|
| **Environment** | `.env`, `.env.local`, `.env.production`, `.env.staging` |
| **Certificates** | `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.keystore` |
| **SSH Keys** | `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519` |
| **Credentials** | `credentials.json`, `service-account.json` |
| **Sensitive Config** | `.npmrc`, `.pypirc`, `.dockercfg`, `.htpasswd` |

---

## Configuration

Generate a default configuration file:

```bash
env-shield init
```

This creates `.env-shield.json` in your repository root:

```json
{
  "ignore_files": [
    "test/fixtures/keys.pem"
  ],
  "ignore_patterns": [
    "\\.test\\.",
    "\\.spec\\."
  ],
  "entropy_threshold": 4.5,
  "min_secret_length": 16,
  "severity": "block",
  "custom_patterns": [
    { "regex": "CORP_KEY_[A-Z0-9]{20}", "name": "Corp Internal Key" }
  ]
}
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `ignore_files` | Exact file paths to skip scanning | `[]` |
| `ignore_patterns` | Regex patterns matching filenames to skip | `["\\.test\\.", "\\.spec\\."]` |
| `entropy_threshold` | Shannon entropy threshold (0–8; higher = stricter) | `4.5` |
| `min_secret_length` | Minimum string length for entropy detection | `16` |
| `severity` | `"block"` (blocks commit) or `"warn"` (prints warnings, allows commit) | `"block"` |
| `custom_patterns` | Organization-specific regex patterns | `[]` |

---

## Bypass Options

### Ignore a Specific Line

Add a comment containing `env-shield-ignore`:

```go
var TestKey = "AKIAIOSFODNN7EXAMPLE" // env-shield-ignore
```

### Ignore an Entire File

Add the file path to `ignore_files` in `.env-shield.json`:

```json
{
  "ignore_files": ["test/testdata/secret.pem"]
}
```

### Ignore by Pattern

Add a regex pattern to `ignore_patterns`:

```json
{
  "ignore_patterns": ["test/fixtures/.*", "mocks/.*"]
}
```

---

## Performance

### Concurrent Worker Pool

```
┌─────────────────────────────────────────────────────┐
│                   ScanStagedFiles                    │
│                                                      │
│  git diff --cached ──► File list                     │
│                              │                       │
│                    ┌─────────▼─────────┐             │
│                    │   Jobs Channel    │             │
│                    │  (chan FileJob)   │             │
│                    └─────────┬─────────┘             │
│              ┌───────────────┼───────────────┐       │
│              │               │               │       │
│         ┌────▼───┐    ┌─────▼────┐   ┌──────▼──┐    │
│         │Worker 1│    │Worker 2  │   │Worker N │    │
│         │stream  │    │stream    │   │stream   │    │
│         │line × N│    │line × N  │   │line × N │    │
│         └────┬───┘    └─────┬────┘   └──────┬──┘    │
│              └───────────────┼───────────────┘       │
│                    ┌─────────▼─────────┐             │
│                    │ Results Channel   │             │
│                    └─────────┬─────────┘             │
│                              ▼                       │
│                    Aggregated findings               │
└─────────────────────────────────────────────────────┘
```

### Constant O(1) Memory

Each file is processed as a **stream** — line by line via `bufio.Scanner` piped from `git show :<file>`. The full file content is **never** loaded into application memory.

| Metric | Value |
|--------|-------|
| **Memory per worker** | O(1) — independent of file size |
| **Throughput** | O(n/m) where n = files, m = workers |
| **Concurrent workers** | 8 (`MaxWorkers` constant) |
| **Allocations in hot path** | 0 — frequency maps use bounded charset |

### Binary File Detection

Env-Shield skips binary files (images, executables, archives) using:

- **Magic numbers** — Reads only the first 6 bytes from the Git stream
- **File extensions** — `.png`, `.jpg`, `.exe`, `.zip`, `.woff2`, `.db`, `.wasm`, etc.
- **Lock files** — `package-lock.json`, `yarn.lock`, `Cargo.lock`, `go.sum`

---

## Languages & Tools

| Category | Technology |
|----------|------------|
| **Language** | Go 1.22+ |
| **Concurrency** | Goroutines + Channels (worker pool pattern) |
| **Testing** | Go `testing` package (unit + integration + benchmarks) |
| **Regex Engine** | Go `regexp` (RE2, linear-time matching) |
| **Git Integration** | `git diff --cached`, `git show`, `git rev-parse` |
| **Build Tool** | `go build` |
| **Platform Support** | Windows, Linux, macOS |

---

## Project Structure

```
env-shield/
├── main.go                     # CLI entry point (install, scan, init, help)
├── go.mod                      # Go module definition
├── README.md                   # This documentation
└── core/
    ├── detector.go             # Detection engine + worker pool + streaming scanner
    ├── detector_test.go        # Unit tests + benchmarks
    ├── integration_test.go     # End-to-end tests with real Git repositories
    ├── output.go               # Console output formatting
    └── install.go              # Hook installation + configuration management
```

---

## Testing

```bash
# Run all tests
go test ./... -v

# Unit tests only
go test ./core -v -run "Test(CalculateEntropy|Obfuscate|Detect)"

# Integration tests only (requires Git installed)
go test ./core -v -run "TestIntegration"

# Benchmarks
go test ./core -bench=. -benchmem

# Tests with code coverage
go test ./... -cover
```

### Test Coverage

```
ok  github.com/hunkak03/env-shield/core  coverage: 64.2% of statements
```

All tests pass across unit, integration, and benchmark suites.

---

## Troubleshooting

### `go: command not found` / `'go' is not recognized`

Go is not in your PATH. Fix per platform:

**Windows CMD:**
```cmd
set PATH=C:\Program Files\Go\bin;%PATH%
```

**Windows PowerShell:**
```powershell
$env:PATH += ";C:\Program Files\Go\bin"
```

**Windows (permanent — add to system environment):**
1. Press `Win + R`, type `sysdm.cpl`, press Enter
2. Go to **Advanced** → **Environment Variables**
3. Under **System variables**, edit `Path` and add `C:\Program Files\Go\bin`
4. Restart your terminal

**Linux / macOS:**
```bash
# Add to your shell profile (~/.bashrc, ~/.zshrc, etc.)
export PATH=$PATH:/usr/local/go/bin
source ~/.bashrc  # or ~/.zshrc
```

> **Tip:** Always **restart your terminal** after installing Go or modifying PATH.

---

### `error: cannot spawn .git/hooks/pre-commit: Permission denied`

The hook file lacks execute permissions.

**Linux / macOS:**
```bash
chmod +x .git/hooks/pre-commit
```

**Windows:**
This usually means Git can't find or execute the hook. Fix by reinstalling:
```cmd
env-shield.exe install
```

If the problem persists, verify your Git hooks path:
```cmd
git config core.hooksPath
```
If it returns nothing, the hook wasn't properly registered. Run `env-shield install` again.

---

### `'env-shield' is not recognized` / `command not found: env-shield`

The binary isn't in your PATH. You have two options:

**Option A — Use the full path every time:**
```cmd
:: Windows
C:\path\to\env-shield.exe install
```
```bash
# Linux / macOS
/path/to/env-shield install
```

**Option B — Add the binary directory to your PATH:**

**Windows CMD:**
```cmd
set PATH=C:\path\to\env-shield\dir;%PATH%
```

**Windows PowerShell (session-only):**
```powershell
$env:PATH += ";C:\path\to\env-shield\dir"
```

**Windows PowerShell (permanent):**
```powershell
[Environment]::SetEnvironmentVariable("PATH", "$env:PATH;C:\path\to\env-shield\dir", "User")
```

**Linux / macOS:**
```bash
echo 'export PATH=$PATH:/path/to/env-shield/dir' >> ~/.bashrc
source ~/.bashrc
```

---

### Hook doesn't run on commit

**Check 1 — Is the hook file there?**
```bash
ls -la .git/hooks/pre-commit          # Linux / macOS
dir .git\hooks\pre-commit             # Windows CMD
Get-Item .git\hooks\pre-commit        # Windows PowerShell
```

**Check 2 — Is Git configured to find it?**
```bash
git config core.hooksPath
```
On Windows, this should return `.git/hooks` (or your hooks directory). If it's empty, run:
```bash
env-shield install
```

**Check 3 — Does the hook reference the correct binary path?**
If you moved the `env-shield` binary after installing the hook, the hook will point to a nonexistent path. Re-run `env-shield install` to update the hook with the new path.

**Check 4 — Windows Git Bash vs. CMD vs. PowerShell**
The hook is a `#!/bin/sh` script. It works with **Git Bash** automatically. If you use CMD or PowerShell, make sure `env-shield install` completed successfully and set `core.hooksPath`.

---

### `fatal: not a git repository`

You're running Env-Shield outside of a Git repository. Make sure you're inside a repo with a `.git` directory:
```bash
git rev-parse --git-dir
```
If this fails, initialize Git first:
```bash
git init
```

---

### `env-shield init` creates config in the wrong place

The config file `.env-shield.json` is created in your **repository root** (not your current directory). Make sure you run `env-shield init` from inside a Git repository:
```bash
cd /path/to/your-repo
env-shield init
```

---

### False positives in test files

Add `// env-shield-ignore` to the specific line, or exclude test files in your config:

```json
{
  "ignore_patterns": ["\\.test\\.", "\\.spec\\.", "test_"]
}
```

---

### Hook is too slow / hangs on large files

Env-Shield streams files line-by-line with constant memory and skips binary files automatically. If a scan is slow, it's likely scanning large text files (e.g., minified JS, generated code). Exclude them:

```json
{
  "ignore_patterns": ["\\.min\\.", "\\.generated\\.", "dist/.*"]
}
```

---

### Uninstall the hook

**Option 1 — Remove the hook file:**
```bash
# Linux / macOS
rm .git/hooks/pre-commit

# Windows CMD
del .git\hooks\pre-commit

# Windows PowerShell
Remove-Item .git\hooks\pre-commit
```

**Option 2 — Reset Git's hooks path (Windows only):**
```bash
git config --unset core.hooksPath
```

**Option 3 — Restore a backed-up hook:**
Env-Shield automatically backs up existing hooks to `.git/hooks/pre-commit.env-shield.bak`. To restore:
```bash
# Linux / macOS
mv .git/hooks/pre-commit.env-shield.bak .git/hooks/pre-commit

# Windows
copy .git\hooks\pre-commit.env-shield.bak .git\hooks\pre-commit
```

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## Author

**Env-Shield** is designed, developed, and maintained by **[Hunkak03](https://github.com/Hunkak03)**.

- 🌐 GitHub: [github.com/Hunkak03](https://github.com/Hunkak03)
- 💼 Project: [github.com/Hunkak03/env-shield](https://github.com/Hunkak03/env-shield)

---

<p align="center">
  Made with 💚 by <strong>Hunkak03</strong>
</p>
