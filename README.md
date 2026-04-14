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

This section walks through the **complete setup process** from zero. Follow each step in order. If you run into issues, see the [Troubleshooting](#troubleshooting) section at the bottom.

---

### Step 1: Install Go

Env-Shield is written in Go and requires **Go 1.22 or later** to compile and run. Pick the instructions for your operating system below.

<details>
<summary><b>Windows — winget (recommended for Windows 10/11)</b></summary>

Open **CMD**, **PowerShell**, or **Windows Terminal** and run:

```cmd
winget install GoLang.Go
```

After installation completes, **close and reopen your terminal** so the `PATH` environment variable updates. Then verify:

```cmd
go version
```

You should see something like `go version go1.23.4 windows/amd64`.

</details>

<details>
<summary><b>Windows — Chocolatey</b></summary>

If you have [Chocolatey](https://chocolatey.org/) installed:

```cmd
choco install golang -y
```

Restart your terminal, then verify:

```cmd
go version
```

</details>

<details>
<summary><b>Windows — Scoop</b></summary>

If you have [Scoop](https://scoop.sh/) installed:

```cmd
scoop install go
```

Restart your terminal, then verify:

```cmd
go version
```

</details>

<details>
<summary><b>Windows — Manual installer</b></summary>

1. Download the installer from [go.dev/dl](https://go.dev/dl/)
2. Run the `.msi` file and follow the wizard
3. The installer automatically adds `C:\Program Files\Go\bin` to your `PATH`
4. **Restart your terminal** and verify:

```cmd
go version
```

</details>

<details>
<summary><b>Linux — Debian / Ubuntu</b></summary>

```bash
sudo apt update && sudo apt install -y golang-go
```

Verify:

```bash
go version
```

> If your distribution's package is too old (< 1.22), use the manual method below.

</details>

<details>
<summary><b>Linux — Fedora / RHEL</b></summary>

```bash
sudo dnf install -y golang
```

Verify:

```bash
go version
```

</details>

<details>
<summary><b>Linux — Arch Linux</b></summary>

```bash
sudo pacman -S go
```

Verify:

```bash
go version
```

</details>

<details>
<summary><b>Linux — Manual install (any distro)</b></summary>

If your package manager doesn't have Go 1.22+:

```bash
# 1. Download the latest Go tarball (replace version as needed)
wget https://go.dev/dl/go1.23.4.linux-amd64.tar.gz -O /tmp/go.tar.gz

# 2. Remove any previous Go installation
sudo rm -rf /usr/local/go

# 3. Extract to /usr/local
sudo tar -C /usr/local -xzf /tmp/go.tar.gz

# 4. Add Go to your PATH (add this line to ~/.bashrc or ~/.zshrc to make it permanent)
export PATH=$PATH:/usr/local/go/bin

# 5. Verify
go version
```

</details>

<details>
<summary><b>macOS — Homebrew</b></summary>

```bash
brew install go
```

Verify:

```bash
go version
```

</details>

<details>
<summary><b>macOS — MacPorts</b></summary>

```bash
sudo port install go
```

Verify:

```bash
go version
```

</details>

<details>
<summary><b>macOS — Manual installer</b></summary>

1. Download the `.pkg` installer from [go.dev/dl](https://go.dev/dl/)
2. Double-click the `.pkg` file and follow the wizard
3. Verify in a **new terminal window**:

```bash
go version
```

</details>

> **⚠️ Important for all platforms:** After installing Go, you **must restart your terminal** before the `go` command becomes available. The `PATH` variable is only reloaded when a new terminal session starts.

---

### Step 2: Clone the Repository

Open your terminal and clone the project:

```bash
git clone https://github.com/Hunkak03/env-shield.git
```

Navigate into the project directory:

```bash
cd env-shield
```

> **Not sure where to clone it?** You can clone it anywhere. Common choices:
> - **Windows:** `C:\Users\<You>\projects\env-shield`
> - **Linux / macOS:** `~/projects/env-shield`

---

### Step 3: Build the Binary

From inside the `env-shield` directory, run:

```bash
go build -o env-shield .
```

This compiles the source code into a standalone executable:

| Platform | Output file |
|----------|-------------|
| **Windows** | `env-shield.exe` |
| **Linux** | `env-shield` |
| **macOS** | `env-shield` |

**Build time:** Usually 5–15 seconds depending on your machine.

> **Windows PowerShell users:** If you see an error about execution policy, you can still build fine. The policy only affects running scripts, not executables. If you get `cannot run .\env-shield.exe`, try:
> ```powershell
> & ".\env-shield.exe" --help
> ```

#### Verify the build

```bash
# Windows CMD
env-shield.exe version

# Windows PowerShell
.\env-shield.exe version

# Linux / macOS
./env-shield version
```

You should see: `Env-Shield v1.0.0`

---

### Step 4: Install the Pre-Commit Hook

Now navigate to **any Git repository** where you want Env-Shield to protect your commits:

```bash
cd /path/to/your-repo
```

Run the install command, pointing to the binary you just built:

```bash
# Windows CMD (if binary is in your PATH)
env-shield.exe install

# Windows PowerShell
.\env-shield.exe install

# Linux / macOS
./env-shield install

# From anywhere on your system (use the full path)
/full/path/to/env-shield install
```

**What happens during installation:**

1. Env-Shield finds your `.git` directory
2. It creates (or updates) `.git/hooks/pre-commit`
3. On **Windows only**, it configures `core.hooksPath` to `.git/hooks` (only if not already set)
4. It backs up any existing `pre-commit` hook to `pre-commit.env-shield.bak`
5. It prints a success message

**Example output:**
```
✅ Env-Shield installed successfully!
   Hook: .git/hooks/pre-commit
   Config: Create .env-shield.json in your repo root to customize.
```

> **⚠️ You need to do this once per repository.** If you have 3 repos and want Env-Shield in all of them, run `env-shield install` inside each one.

---

### Step 5: (Optional) Create a Configuration File

If you want to customize detection — like ignoring certain files, adjusting sensitivity, or adding your company's secret formats — run:

```bash
# From inside your repo
env-shield init          # or ./env-shield init on Linux/macOS
```

This creates `.env-shield.json` in your repository's root directory with sensible defaults:

```json
{
  "ignore_files": [],
  "ignore_patterns": ["\\.test\\.", "\\.spec\\.", "test_", "_test\\."],
  "entropy_threshold": 4.5,
  "min_secret_length": 16,
  "severity": "block",
  "custom_patterns": []
}
```

> The config file is **optional**. Env-Shield works perfectly fine without it — it just uses built-in defaults instead.

---

### Step 6: Verify Everything Works

Create a test file with a fake secret:

```bash
# Create a test file
echo 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"' > test_secret.txt

# Stage it
git add test_secret.txt

# Try to commit
git commit -m "test: trigger env-shield"
```

Env-Shield should **block the commit** and display a report like:

```
============================================================
  🛡️  Env-Shield: SECRETS DETECTED!
============================================================
  Found 1 potential secret(s) in 1 staged file(s).
  🚫 1 finding(s) BLOCK commit.
  ...
```

Now clean up:

```bash
# Unstage the file
git reset HEAD test_secret.txt

# Delete it
rm test_secret.txt          # Linux / macOS
del test_secret.txt         # Windows CMD
Remove-Item test_secret.txt # Windows PowerShell
```

**You're all set!** 🎉

---

### Making `env-shield` Available Globally (Optional)

If you're tired of typing the full path every time, add the binary directory to your `PATH`:

<details>
<summary><b>Windows CMD — session only</b></summary>

```cmd
set PATH=C:\path\to\env-shield\dir;%PATH%
```

This only lasts until you close the terminal.

</details>

<details>
<summary><b>Windows CMD — permanent</b></summary>

```cmd
setx PATH "%PATH%;C:\path\to\env-shield\dir"
```

Then **restart your terminal**.

</details>

<details>
<summary><b>Windows PowerShell — session only</b></summary>

```powershell
$env:PATH += ";C:\path\to\env-shield\dir"
```

This only lasts until you close the terminal.

</details>

<details>
<summary><b>Windows PowerShell — permanent (current user)</b></summary>

```powershell
[Environment]::SetEnvironmentVariable(
    "PATH",
    "$([Environment]::GetEnvironmentVariable('PATH', 'User'));C:\path\to\env-shield\dir",
    "User"
)
```

Restart your terminal. This only affects your user account.

</details>

<details>
<summary><b>Windows PowerShell — permanent (system-wide, requires admin)</b></summary>

```powershell
[Environment]::SetEnvironmentVariable(
    "PATH",
    "$([Environment]::GetEnvironmentVariable('PATH', 'Machine'));C:\path\to\env-shield\dir",
    "Machine"
)
```

Restart your terminal. This affects all users on the machine.

</details>

<details>
<summary><b>Linux / macOS — Bash</b></summary>

Add this line to your `~/.bashrc`:

```bash
export PATH=$PATH:/path/to/env-shield/dir
```

Then reload:

```bash
source ~/.bashrc
```

</details>

<details>
<summary><b>Linux / macOS — Zsh (default on modern macOS)</b></summary>

Add this line to your `~/.zshrc`:

```bash
export PATH=$PATH:/path/to/env-shield/dir
```

Then reload:

```bash
source ~/.zshrc
```

</details>

<details>
<summary><b>Linux / macOS — Fish</b></summary>

```bash
set -Ux PATH $PATH /path/to/env-shield/dir
```

No need to source — Fish applies this immediately.

</details>

After adding to PATH, verify it works:

```bash
env-shield --help
# or on Windows:
env-shield.exe --help
```

---

## Usage

This section explains **how to use Env-Shield day-to-day**, every available command, and what happens behind the scenes when you commit.

---

### Available Commands

| Command | Description | When to use |
|---------|-------------|-------------|
| `env-shield install` | Install the pre-commit hook in the current repository | Once per repo, during initial setup |
| `env-shield scan` | Scan currently staged files for secrets | Anytime, to manually check staged files |
| `env-shield init` | Generate a default `.env-shield.json` configuration file | When you want to customize detection |
| `env-shield version` | Display version information | To check which version you're running |
| `env-shield help` | Show help and usage | Quick reference for available commands |

---

### How Env-Shield Works (Behind the Scenes)

When you run `env-shield install`, the following happens:

1. **A `pre-commit` hook file is created** at `.git/hooks/pre-commit`
2. **The hook is a small shell script** that runs `env-shield scan` every time you commit
3. **Git calls the hook automatically** before each commit — you don't need to do anything

```
Your workflow:                    What Env-Shield does:
┌─────────────────────┐          ┌──────────────────────────────┐
│ git add file.txt    │          │                                │
│ git commit -m "..." │ ────────►│ pre-commit hook fires         │
└─────────────────────┘          │                                │
                                 │ 1. Gets list of staged files   │
                                 │ 2. Scans each file for secrets │
                                 │ 3. If secrets found → BLOCK    │
                                 │ 4. If clean → allow commit     │
                                 └──────────────────────────────┘
```

---

### Step-by-Step: Daily Workflow

#### Step 1 — Install the hook (one time per repo)

```bash
cd your-repo
env-shield install
```

You only do this once. After that, Env-Shield protects every commit automatically.

#### Step 2 — Work normally

```bash
# Edit some files
echo 'DATABASE_URL = "postgres://user:pass@localhost/db"' > config.py

# Stage them
git add config.py

# Commit as usual
git commit -m "add database configuration"
```

Env-Shield intercepts the commit and scans `config.py` in the background. If it finds a database connection string (which it will), the commit is **blocked** with a detailed report.

#### Step 3 — Fix the issue and re-commit

After the block, you have a few options:

**Option A — Remove the secret** (recommended):
```bash
# Move the secret to a .env file (which is blocked by default) or use environment variables
echo 'DATABASE_URL = os.environ.get("DATABASE_URL")' > config.py
git add config.py
git commit -m "use environment variable for database URL"
# ✅ Commit succeeds
```

**Option B — Ignore the specific line** (if it's test data):
```bash
# Add the env-shield-ignore comment
echo 'DATABASE_URL = "postgres://user:pass@localhost/db" // env-shield-ignore' > config.py
git add config.py
git commit -m "add test config"
# ✅ Commit succeeds
```

**Option C — Ignore the file in config**:
```bash
env-shield init  # if you haven't already
```

Then edit `.env-shield.json`:
```json
{
  "ignore_files": ["config.py"]
}
```

```bash
git commit -m "add config"
# ✅ Commit succeeds
```

---

### Command Reference — Detailed

#### `env-shield install`

Installs the pre-commit hook into the current Git repository.

**Usage:**
```bash
# From inside any repo
env-shield install
```

**What it does:**
- Locates your `.git` directory (works even in submodules and bare repos)
- Creates `.git/hooks/pre-commit` with a script that calls `env-shield scan`
- Backs up any existing hook to `.git/hooks/pre-commit.env-shield.bak`
- On Windows: sets `core.hooksPath` (only if not already configured)

**Example output:**
```
✅ Env-Shield installed successfully!
   Hook: .git/hooks/pre-commit
   Config: Create .env-shield.json in your repo root to customize.
```

**Common errors:**
- `not a git repository` — You're not inside a Git repo. Run `git init` first.
- `could not set core.hooksPath` — Non-critical warning on Windows. The hook still works.

---

#### `env-shield scan`

Scans all currently staged files for secrets. This is the command the pre-commit hook runs automatically, but you can also run it manually at any time.

**Usage:**
```bash
# Stage some files first
git add config.py secrets.txt .env

# Then scan them
env-shield scan
```

**What it does:**
- Gets the list of staged files via `git diff --cached --name-only`
- Skips binary files (images, executables, lock files)
- Skips files listed in `ignore_files` or matching `ignore_patterns` in `.env-shield.json`
- Runs three detection layers on each file:
  1. **Regex patterns** — matches known secret formats (AWS keys, Stripe keys, etc.)
  2. **Shannon entropy** — identifies high-randomness strings that look like tokens
  3. **Forbidden files** — blocks known-sensitive filenames (`.env`, `.pem`, `id_rsa`, etc.)
- Prints a report and exits with code `1` if any findings would block the commit

**Exit codes:**
| Code | Meaning |
|------|----------|
| `0` | No blocking findings — commit would be allowed |
| `1` | Blocking findings found — commit should be blocked |

**Example output — secrets found:**
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

**Example output — clean scan:**
```
✅ Env-Shield: No secrets detected. (scanned 5 files in 23ms)
```

---

#### `env-shield init`

Generates a default `.env-shield.json` configuration file in your repository root.

**Usage:**
```bash
# Run from anywhere inside your repo
env-shield init
```

**What it does:**
- Finds your repository root (even if you're in a subdirectory)
- Creates `.env-shield.json` if it doesn't already exist
- If it already exists, prints a warning and does nothing (won't overwrite)

**Example output:**
```
✅ Created default .env-shield.json
```

Or if it already exists:
```
⚠️  Config file .env-shield.json already exists.
```

**Where is the file created?**
In your repository's root directory (the same directory that contains `.git`). Not your current working directory — so even if you're deep in a subfolder, the config goes to the right place.

---

#### `env-shield version`

Displays the current version of Env-Shield.

**Usage:**
```bash
env-shield version
# or
env-shield --version
# or
env-shield -v
```

**Output:**
```
Env-Shield v1.0.0
```

---

#### `env-shield help`

Displays a summary of available commands.

**Usage:**
```bash
env-shield help
# or
env-shield --help
# or
env-shield -h
```

---

### Platform-Specific Usage Examples

Below are concrete examples for every common environment. Replace paths as needed.

<details>
<summary><b>Windows CMD</b></summary>

```cmd
:: Navigate to your project
cd C:\Users\You\projects\my-app

:: Install the hook
..\env-shield\env-shield.exe install

:: Manual scan
..\env-shield\env-shield.exe scan

:: Create config
..\env-shield\env-shield.exe init

:: Check version
..\env-shield\env-shield.exe version
```

</details>

<details>
<summary><b>Windows PowerShell</b></summary>

```powershell
# Navigate to your project
Set-Location C:\Users\You\projects\my-app

# Install the hook
.\env-shield.exe install

# Manual scan
.\env-shield.exe scan

# Create config
.\env-shield.exe init

# Check version
.\env-shield.exe version
```

If the binary is **not** in your current directory, use the full path:
```powershell
& "C:\tools\env-shield\env-shield.exe" install
```

</details>

<details>
<summary><b>Windows Git Bash</b></summary>

```bash
# Navigate to your project (uses Unix-style paths)
cd /c/Users/You/projects/my-app

# Install the hook
./env-shield.exe install

# Manual scan
./env-shield.exe scan

# Create config
./env-shield.exe init

# Check version
./env-shield.exe version
```

</details>

<details>
<summary><b>Windows Terminal (with WSL)</b></summary>

If you're using WSL (Windows Subsystem for Linux) and have Go installed inside WSL:

```bash
# Navigate to your project (accessible via /mnt/c/)
cd /mnt/c/Users/You/projects/my-app

# Install the hook
./env-shield install

# Manual scan
./env-shield scan
```

> Note: WSL has its own Go installation. You need to build `env-shield` inside WSL separately if you want a native Linux binary for WSL.

</details>

<details>
<summary><b>Linux — Bash</b></summary>

```bash
# Navigate to your project
cd ~/projects/my-app

# Install the hook
./env-shield install

# Manual scan
./env-shield scan

# Create config
./env-shield init

# Check version
./env-shield version
```

</details>

<details>
<summary><b>Linux — Zsh</b></summary>

Same commands as Bash (Zsh is fully compatible):

```bash
cd ~/projects/my-app
./env-shield install
./env-shield scan
./env-shield init
./env-shield version
```

</details>

<details>
<summary><b>Linux — Fish</b></summary>

```fish
# Navigate to your project
cd ~/projects/my-app

# Install the hook
./env-shield install

# Manual scan
./env-shield scan
```

</details>

<details>
<summary><b>macOS — Terminal (zsh is default)</b></summary>

```bash
# Navigate to your project
cd ~/projects/my-app

# Install the hook
./env-shield install

# Manual scan
./env-shield scan

# Create config
./env-shield init

# Check version
./env-shield version
```

</details>

<details>
<summary><b>Running from anywhere (binary in PATH)</b></summary>

Once you've added `env-shield` to your `PATH` (see [Installation](#installation)), you can run it from any directory without a path prefix:

```bash
# From any directory
cd ~/projects/some-other-repo
env-shield install
env-shield scan
env-shield init
```

This works the same on all platforms.

</details>

---

### Understanding the Scan Report

When Env-Shield detects secrets, it prints a structured report. Here's what each field means:

```
  [1] File: config/settings.go    ← The file that triggered the finding
      Line: 15                     ← Line number (0 = entire file, e.g. forbidden file)
      Type: AWS Access Key ID      ← What kind of secret was detected
      Layer: regex                 ← Which detection layer found it
      Severity: block              ← "block" prevents commit, "warn" allows it
      Value: AKIA...MPLE           ← The secret, obfuscated for safety
```

**Detection layers explained:**

| Layer | What it does | Example |
|-------|-------------|---------|
| `regex` | Matches known secret patterns | AWS keys, Stripe tokens, JWTs |
| `entropy` | Flags high-randomness strings | `xK9mP2vLqR7nW4jTsY8aB3cD5eF` |
| `forbidden_file` | Blocks sensitive filenames | `.env`, `.pem`, `id_rsa` |
| `custom` | Your organization's regex patterns | Defined in `.env-shield.json` |

---

### Severity Levels: `block` vs `warn`

Env-Shield supports two severity modes, controlled by the `severity` field in `.env-shield.json`:

**`"block"` (default):**
Findings with this severity **prevent the commit** (exit code 1). Use this for production repositories where any secret leak must be stopped.

**`"warn"`:**
Findings are **printed but the commit is allowed** (exit code 0). Useful for:
- Migration periods where you're gradually cleaning up secrets
- Teams that want visibility without blocking productivity
- CI pipelines that log warnings but don't want to break builds yet

**Example `.env-shield.json` with warn mode:**
```json
{
  "severity": "warn"
}
```

---

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

This section covers **every common issue** users encounter, organized by symptom. Each entry includes platform-specific fixes.

> **Before you start:** Make sure you've completed all steps in the [Installation](#installation) guide. Many issues are caused by skipping a step or not restarting the terminal after installing Go.

---

### Go Installation Issues

<details>
<summary><b><code>go: command not found</code> (Linux / macOS)</b></summary>

**What it means:** Your shell can't find the `go` binary. This usually means Go isn't installed or isn't in your `PATH`.

**Quick fix:**

```bash
# Try the default location
/usr/local/go/bin/go version
```

If that works, Go is installed but your `PATH` isn't configured. Make it permanent:

**For Bash (`~/.bashrc`):**
```bash
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

**For Zsh (`~/.zshrc`):**
```bash
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc
source ~/.zshrc
```

**For Fish:**
```fish
set -Ux PATH $PATH /usr/local/go/bin
```

**If `/usr/local/go/bin/go version` also fails:** Go isn't installed. Go back to [Step 1 of Installation](#installation) and install it.

</details>

<details>
<summary><b><code>'go' is not recognized as an internal or external command</code> (Windows CMD)</b></summary>

**What it means:** The `go` binary isn't in your `PATH` environment variable.

**Quick fix (current session only):**

```cmd
set PATH=C:\Program Files\Go\bin;%PATH%
go version
```

This only lasts until you close the terminal. To fix it **permanently**:

**Method 1 — Using `setx` (command line):**
```cmd
setx PATH "%PATH%;C:\Program Files\Go\bin"
```
Then **close and reopen** your terminal.

**Method 2 — Using the GUI (recommended for beginners):**
1. Press `Win + R`, type `sysdm.cpl`, press Enter
2. Click the **Advanced** tab
3. Click **Environment Variables**
4. Under **System variables**, find `Path` and click **Edit**
5. Click **New** and add: `C:\Program Files\Go\bin`
6. Click **OK** on all dialogs
7. **Restart your terminal** and try again

**Method 3 — Using PowerShell (permanent):**
```powershell
[Environment]::SetEnvironmentVariable(
    "Path",
    "$([Environment]::GetEnvironmentVariable('Path', 'User'));C:\Program Files\Go\bin",
    "User"
)
```
Restart your terminal.

</details>

<details>
<summary><b><code>go: command not found</code> (Windows PowerShell)</b></summary>

**Quick fix (current session only):**

```powershell
$env:PATH += ";C:\Program Files\Go\bin"
go version
```

**Permanent fix:** Use Method 2 or Method 3 from the CMD section above.

</details>

<details>
<summary><b>Go version is too old (< 1.22)</b></summary>

Your package manager may have an outdated version. Fix it:

**Linux (manual upgrade):**
```bash
# Remove old version
sudo rm -rf /usr/local/go

# Download and install the latest
wget https://go.dev/dl/go1.23.4.linux-amd64.tar.gz -O /tmp/go.tar.gz
sudo tar -C /usr/local -xzf /tmp/go.tar.gz
export PATH=$PATH:/usr/local/go/bin  # Add to ~/.bashrc or ~/.zshrc to make permanent
go version
```

**macOS (Homebrew):**
```bash
brew upgrade go
go version
```

**Windows:**
Re-run the installer from [go.dev/dl](https://go.dev/dl/) — it will replace the old version.

</details>

---

### Build Issues

<details>
<summary><b><code>package github.com/hunkak03/env-shield/core: cannot find package</code></b></summary>

**What it means:** You're trying to build from outside the project directory, or you didn't `cd env-shield` after cloning.

**Fix:**
```bash
cd env-shield
go build -o env-shield .
```

</details>

<details>
<summary><b><code>go: go.mod file not found</code></b></summary>

**What it means:** You're not in the project root. The `go.mod` file must be in the current directory or a parent directory.

**Fix:** Navigate to the directory that contains `go.mod`:
```bash
cd path/to/env-shield
go build -o env-shield .
```

</details>

<details>
<summary><b><code>build constraints exclude all Go files</code></b></summary>

**What it means:** This is rare, but can happen if your Go installation is corrupted or you're using an incompatible Go version.

**Fix:**
1. Verify your Go version: `go version` (must be 1.22+)
2. Reinstall Go from [go.dev/dl](https://go.dev/dl/)
3. Clean the build cache: `go clean -cache`
4. Try building again: `go build -o env-shield .`

</details>

<details>
<summary><b>Build takes too long (> 1 minute)</b></summary>

This shouldn't happen — Env-Shield has zero external dependencies and builds in 5–15 seconds. If it's slow:

1. Check your disk space: `df -h` (Linux/macOS) or `dir C:\` (Windows)
2. Clear the Go build cache: `go clean -cache`
3. Try again: `go build -o env-shield .`

If it's still slow, your machine may be under heavy load. Check with `top` (Linux/macOS) or Task Manager (Windows).

</details>

---

### Hook Installation Issues

<details>
<summary><b><code>not a git repository: run 'git init' first</code></b></summary>

**What it means:** You're running `env-shield install` outside of a Git repository.

**Fix:** Navigate to a Git repository first:
```bash
cd /path/to/your-repo
env-shield install
```

If the repo doesn't exist yet, create it:
```bash
mkdir my-project
cd my-project
git init
env-shield install
```

**How to check if you're in a Git repo:**
```bash
git rev-parse --git-dir
```
If this prints `.git` (or a path), you're in a repo. If it prints an error, you're not.

</details>

<details>
<summary><b>Hook file doesn't exist after install</b></summary>

After running `env-shield install`, the hook file should be at `.git/hooks/pre-commit`. Check:

**Linux / macOS:**
```bash
ls -la .git/hooks/pre-commit
```

**Windows CMD:**
```cmd
dir .git\hooks\pre-commit
```

**Windows PowerShell:**
```powershell
Get-Item .git\hooks\pre-commit
```

If the file doesn't exist:
1. Check that `.git/hooks/` exists: `ls .git/hooks/` or `dir .git\hooks\`
2. If the `hooks` directory is missing, your Git installation may be corrupted
3. Re-run `env-shield install`

</details>

<details>
<summary><b>Hook installs but points to the wrong binary path</b></summary>

If you moved the `env-shield` binary after installing the hook, the hook will reference a nonexistent path.

**Fix:** Re-run install to update the hook with the correct path:
```bash
env-shield install
```

**To check what path the hook currently uses:**

**Linux / macOS:**
```bash
cat .git/hooks/pre-commit
```

**Windows:**
```cmd
type .git\hooks\pre-commit
```

Look for the line containing `env-shield` — that's the path the hook calls.

</details>

---

### Hook Execution Issues

<details>
<summary><b><code>error: cannot spawn .git/hooks/pre-commit: Permission denied</code></b></summary>

**What it means:** The hook file doesn't have execute permissions (Linux/macOS) or Git can't find it (Windows).

**Linux / macOS fix:**
```bash
chmod +x .git/hooks/pre-commit
```

**Windows fix:**
This error on Windows usually means `core.hooksPath` isn't set correctly. Fix it:
```bash
git config core.hooksPath ".git/hooks"
```

Or simply reinstall the hook:
```bash
env-shield install
```

</details>

<details>
<summary><b><code>cannot spawn .git/hooks/pre-commit: No such file or directory</code></b></summary>

**What it means:** The hook file was deleted or never created.

**Fix:**
```bash
env-shield install
```

If you previously had other custom hooks in `.git/hooks/pre-commit`, they were backed up to `.git/hooks/pre-commit.env-shield.bak`. You can restore them if needed.

</details>

<details>
<summary><b>Hook doesn't run on commit (silent failure)</b></summary>

If you commit and Env-Shield doesn't seem to run at all, follow this checklist:

**Step 1 — Is the hook file there?**
```bash
# Linux / macOS
ls -la .git/hooks/pre-commit

# Windows CMD
dir .git\hooks\pre-commit

# Windows PowerShell
Get-Item .git\hooks\pre-commit
```

If the file doesn't exist → run `env-shield install`.

**Step 2 — Does the hook have execute permissions?** (Linux/macOS only)
```bash
ls -l .git/hooks/pre-commit
```
You should see `-rwxr-xr-x`. If not, run: `chmod +x .git/hooks/pre-commit`

**Step 3 — Is Git configured to find the hook?**
```bash
git config core.hooksPath
```
On Windows, this should return `.git/hooks`. If it returns nothing:
```bash
git config core.hooksPath ".git/hooks"
```

**Step 4 — Does the hook reference the correct binary?**
```bash
# Linux / macOS
cat .git/hooks/pre-commit

# Windows
type .git\hooks\pre-commit
```
Look for the line with `env-shield`. Verify that path exists:
```bash
ls /path/to/env-shield       # Linux / macOS
dir C:\path\to\env-shield.exe  # Windows
```

**Step 5 — Are you using the right terminal on Windows?**
The hook is a `#!/bin/sh` script. Behavior differs by terminal:

| Terminal | Does it work? | Notes |
|----------|---------------|-------|
| **Git Bash** | ✅ Yes | Native sh support |
| **CMD** | ⚠️ Needs `core.hooksPath` | Env-Shield sets this automatically |
| **PowerShell** | ⚠️ Needs `core.hooksPath` | Env-Shield sets this automatically |
| **WSL** | ✅ Yes | Uses Linux binary |

**Step 6 — Test the hook manually:**
```bash
# Run the hook script directly
sh .git/hooks/pre-commit
echo $?
# Exit code 0 = no staged files, exit code 1 = secrets found
```

</details>

<details>
<summary><b>Hook runs but seems to hang / takes forever</b></summary>

Env-Shield has a **30-second timeout** on all Git operations. If a scan hangs:

1. The file may be very large (minified JS, generated code). Exclude it:
   ```json
   { "ignore_patterns": ["dist/.*", "build/.*", ".*\\.min\\.js"] }
   ```
2. The Git repository may be corrupt. Try: `git fsck`
3. Your system may be under heavy load. Check with `top` or Task Manager.

If the scan exceeds 30 seconds, Git kills the process and the commit fails with a timeout error.

</details>

---

### Binary / PATH Issues

<details>
<summary><b><code>'env-shield' is not recognized</code> / <code>command not found: env-shield</code></b></summary>

**What it means:** The `env-shield` binary isn't in your `PATH`.

**Option A — Use the full path (quick fix):**

```cmd
:: Windows
C:\path\to\env-shield.exe install
```

```bash
# Linux / macOS
/path/to/env-shield install
```

**Option B — Add the binary directory to your PATH (permanent):**

**Windows CMD:**
```cmd
setx PATH "%PATH%;C:\path\to\env-shield\dir"
```
Restart your terminal.

**Windows PowerShell (current user):**
```powershell
[Environment]::SetEnvironmentVariable(
    "PATH",
    "$([Environment]::GetEnvironmentVariable('PATH', 'User'));C:\path\to\env-shield\dir",
    "User"
)
```

**Linux / macOS (Bash):**
```bash
echo 'export PATH=$PATH:/path/to/env-shield/dir' >> ~/.bashrc
source ~/.bashrc
```

**Linux / macOS (Zsh):**
```bash
echo 'export PATH=$PATH:/path/to/env-shield/dir' >> ~/.zshrc
source ~/.zshrc
```

</details>

<details>
<summary><b><code>Access is denied</code> when running the binary (Windows)</b></summary>

**What it means:** Windows SmartScreen or your antivirus is blocking the executable.

**Fix:**
1. Right-click the `.exe` file → **Properties**
2. Check **Unblock** at the bottom of the General tab
3. Click **Apply** and **OK**
4. Try running again

If your antivirus quarantined the file, add an exception for the directory. Env-Shield is a clean Go binary with no malware.

</details>

<details>
<summary><b>PowerShell execution policy error</b></summary>

If you see:
```
cannot be loaded because running scripts is disabled on this system
```

This only applies to `.ps1` script files, **not** to `.exe` binaries. You can run `.\env-shield.exe` directly:

```powershell
& ".\env-shield.exe" install
```

</details>

---

### Detection Issues

<details>
<summary><b>False positives — test files flagged</b></summary>

If Env-Shield flags test fixtures, mock data, or example code:

**Quick fix — ignore the line:**
```python
API_KEY = "test_key_12345"  # env-shield-ignore
```

**Better fix — ignore test files in config:**
```bash
env-shield init
```

Then edit `.env-shield.json`:
```json
{
  "ignore_patterns": [
    "\\.test\\.",
    "\\.spec\\.",
    "test_",
    "_test\\.",
    "fixtures/.*",
    "mocks/.*"
  ]
}
```

**Even better — move test secrets to a separate file** that's in your `.gitignore`.

</details>

<details>
<summary><b>False positives — generated / minified files flagged</b></summary>

Generated files (e.g., `dist/bundle.min.js`, `build/output.js`) often contain long base64 strings or random-looking tokens that trigger entropy detection.

**Fix — exclude them in config:**
```json
{
  "ignore_patterns": [
    "dist/.*",
    "build/.*",
    ".*\\.min\\.",
    ".*\\.generated\\."
  ]
}
```

> **Best practice:** Generated files shouldn't be committed anyway. Add them to `.gitignore`.

</details>

<details>
<summary><b>False negatives — secret not detected</b></summary>

If a known secret type isn't being caught:

1. **Check the regex patterns** — Env-Shield matches specific formats. A slightly different format may not match.
2. **Check if the file is being scanned** — binary files and lock files are skipped:
   ```bash
   env-shield scan
   # Look for "Files skipped (binary/ignored): X"
   ```
3. **Check if the file is ignored** — look at `ignore_files` and `ignore_patterns` in `.env-shield.json`.
4. **The secret may have low entropy** — short or predictable strings may not pass the entropy threshold.

If you're sure it should be detected, [open an issue](https://github.com/Hunkak03/env-shield/issues) with the secret format (use a fake/example value, not a real secret).

</details>

<details>
<summary><b><code>.env</code> file not blocked</b></summary>

The `.env` file is blocked by default via Layer 3 (forbidden files). If it's not being blocked:

1. Verify the file is staged: `git status`
2. Check it's not in `ignore_files` in `.env-shield.json`
3. Run a manual scan: `env-shield scan` and check the output

</details>

---

### Config File Issues

<details>
<summary><b><code>env-shield init</code> creates config in the wrong directory</b></summary>

The config file `.env-shield.json` is created in your **repository root** (where `.git` lives), not your current directory.

If you're in a subdirectory:
```bash
cd ~/projects/my-app/src/components
env-shield init
# Config is created at ~/projects/my-app/.env-shield.json (correct)
```

This is intentional — the config should live at the repo root so it applies to all subdirectories.

If the config isn't being picked up, verify it's at the repo root:
```bash
git rev-parse --show-toplevel
# Then check: ls $(git rev-parse --show-toplevel)/.env-shield.json
```

</details>

<details>
<summary><b>Config file has no effect — secrets still detected / not detected</b></summary>

Make sure:
1. The config file is named `.env-shield.json` (with the leading dot)
2. It's in your repository root
3. The JSON is valid (test with `python -m json.tool .env-shield.json` or an online JSON validator)
4. You're not overriding settings with defaults

**Common JSON mistakes:**
- Trailing commas: `"key": "value",}` → remove the last comma
- Unescaped backslashes: `"\.test\."` → should be `"\\.test\\."`
- Single quotes: `{'key': 'value'}` → use double quotes `{"key": "value"}`

</details>

<details>
<summary><b>Custom regex patterns don't work</b></summary>

If patterns in `custom_patterns` aren't matching:

1. **Verify the regex syntax** — Go uses [RE2](https://github.com/google/re2/wiki/Syntax). Test your regex at [regex101.com](https://regex101.com) (select Go/RE2 flavor).
2. **Check the JSON escaping** — backslashes must be doubled:
   ```json
   {"regex": "MY_KEY_[A-Z]{20}", "name": "My Key"}
   ```
3. **Test with `env-shield scan`** on a file containing a matching value.

**Example custom pattern:**
```json
{
  "custom_patterns": [
    {"regex": "CORP_SECRET_[A-Za-z0-9]{32}", "name": "Corp Secret"}
  ]
}
```

</details>

---

### Uninstall / Cleanup

<details>
<summary><b>How to uninstall Env-Shield</b></summary>

**Step 1 — Remove the hook:**

```bash
# Linux / macOS
rm .git/hooks/pre-commit

# Windows CMD
del .git\hooks\pre-commit

# Windows PowerShell
Remove-Item .git\hooks\pre-commit
```

**Step 2 — Reset Git's hooks path (Windows only):**
```bash
git config --unset core.hooksPath
```

On Linux/macOS, Git uses the default `.git/hooks` path, so nothing needs to be reset.

**Step 3 — (Optional) Restore your previous hook:**
If you had a hook before installing Env-Shield, it was backed up:
```bash
# Linux / macOS
mv .git/hooks/pre-commit.env-shield.bak .git/hooks/pre-commit

# Windows
copy .git\hooks\pre-commit.env-shield.bak .git\hooks\pre-commit
```

**Step 4 — (Optional) Delete the binary:**
```bash
# Delete the env-shield binary from wherever you built it
rm env-shield          # Linux / macOS
del env-shield.exe     # Windows
```

**Step 5 — (Optional) Remove the config file:**
```bash
rm .env-shield.json    # From your repo root
```

</details>

<details>
<summary><b>How to temporarily disable the hook (without uninstalling)</b></summary>

If you need to make a commit without Env-Shield checking it:

**Method 1 — Skip the hook for one commit:**
```bash
git commit --no-verify -m "bypass hook"
```
> ⚠️ Only do this if you're sure the commit is clean.

**Method 2 — Temporarily rename the hook:**
```bash
# Linux / macOS
mv .git/hooks/pre-commit .git/hooks/pre-commit.disabled

# Make your commits
git commit -m "something"

# Restore the hook
mv .git/hooks/pre-commit.disabled .git/hooks/pre-commit
```

**Method 3 — Use severity "warn" mode:**
Edit `.env-shield.json`:
```json
{"severity": "warn"}
```
This lets commits through but still prints warnings.
</details>

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
