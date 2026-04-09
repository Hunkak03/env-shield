package core

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ============================================================
// Configuration constants
// ============================================================

const (
	EntropyThreshold  = 4.5
	MinSecretLength   = 16
	MaxWorkers        = 8
	LineBufferSize    = 256 // initial bufio.Scanner buffer
	ConfigFilename    = ".env-shield.json"
)

// ============================================================
// Secret patterns (Layer 1 - Regex)
// ============================================================

type SecretPattern struct {
	Regex *regexp.Regexp
	Name  string
}

var SecretPatterns = []SecretPattern{
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "AWS Access Key ID"},
	{regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key)\s*=\s*[A-Za-z0-9/+=]{40}`), "AWS Secret Access Key"},
	{regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`), "Stripe Secret Key"},
	{regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24,}`), "Stripe Restricted Key"},
	{regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`), "Stripe Publishable Key"},
	{regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), "Google API Key"},
	{regexp.MustCompile(`ya29\.[A-Za-z0-9_-]+`), "Google OAuth Token"},
	{regexp.MustCompile(`ghp_[A-Za-z0-9_]{36,}`), "GitHub Personal Access Token"},
	{regexp.MustCompile(`gho_[A-Za-z0-9_]{36,}`), "GitHub OAuth Token"},
	{regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82,}`), "GitHub Fine-Grained PAT"},
	{regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}`), "Slack Bot Token"},
	{regexp.MustCompile(`xoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}`), "Slack User Token"},
	{regexp.MustCompile(`(?i)(api_key|apikey|secret|password|passwd|pwd|token|auth_token|access_token)\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}["']?`), "Generic API Key/Secret"},
	{regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), "Private Key"},
	{regexp.MustCompile(`(?i)(mongodb|postgres|mysql|redis)://[^\s]+`), "Database Connection String"},
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), "JWT Token"},
}

// ============================================================
// Forbidden files (Layer 3)
// ============================================================

var ForbiddenFilenames = map[string]struct{}{
	".env": {}, ".env.local": {}, ".env.production": {}, ".env.staging": {},
	"id_rsa": {}, "id_dsa": {}, "id_ecdsa": {}, "id_ed25519": {},
	"authorized_keys": {}, "known_hosts": {},
	"htpasswd": {}, ".htpasswd": {},
	"credentials.json": {}, "service-account.json": {},
	".npmrc": {}, ".pypirc": {}, ".dockercfg": {},
}

var ForbiddenExtensions = map[string]struct{}{
	".pem": {}, ".key": {}, ".p12": {}, ".pfx": {}, ".jks": {}, ".keystore": {},
	".env": {}, ".htpasswd": {},
}

// ============================================================
// Data types
// ============================================================

// Severity level for findings
type Severity string

const (
	SeverityBlock Severity = "block" // Blocks commit (default)
	SeverityWarn  Severity = "warn"  // Warns but allows commit
)

type Finding struct {
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Type     string   `json:"type"`
	Secret   string   `json:"secret"`
	Layer    string   `json:"layer"`
	Severity Severity `json:"severity"`
}

// ScanResult aggregates findings with performance metrics
type ScanResult struct {
	Findings      []Finding
	FilesScanned  int
	FilesSkipped  int // Binary or ignored files
	Duration      time.Duration
	BlockedCount  int // Findings with severity=block
	WarnedCount   int // Findings with severity=warn
}

type Config struct {
	IgnoreFiles      []string `json:"ignore_files"`
	IgnorePatterns   []string `json:"ignore_patterns"`
	EntropyThreshold float64  `json:"entropy_threshold"`
	MinSecretLength  int      `json:"min_secret_length"`
	Severity         Severity `json:"severity"` // "block" (default) or "warn"
	CustomPatterns   []struct {
		Regex string `json:"regex"`
		Name  string `json:"name"`
	} `json:"custom_patterns"`
	compiledIgnores   []*regexp.Regexp
	compiledCustoms   []SecretPattern
}

// ============================================================
// Binary file detection (magic numbers)
// ============================================================

// Binary magic number signatures — first bytes of common binary formats
var binarySignatures = []struct {
	magic []byte
	ext   string
}{
	{[]byte{0x89, 0x50, 0x4E, 0x47}, ".png"},       // PNG
	{[]byte{0xFF, 0xD8, 0xFF}, ""},                   // JPEG
	{[]byte{0x47, 0x49, 0x46, 0x38}, ".gif"},         // GIF
	{[]byte{0x42, 0x4D}, ".bmp"},                     // BMP
	{[]byte{0x50, 0x4B, 0x03, 0x04}, ".zip"},         // ZIP/JAR/DOCX/XLSX
	{[]byte{0x7F, 0x45, 0x4C, 0x46}, ".elf"},         // ELF binary
	{[]byte{0x4D, 0x5A}, ".exe"},                     // PE (Windows executable)
	{[]byte{0xCA, 0xFE, 0xBA, 0xBE}, ".class"},       // Java class
	{[]byte{0xFE, 0xED, 0xFA, 0xCE}, ""},             // Mach-O
	{[]byte{0x1F, 0x8B}, ".gz"},                      // Gzip
	{[]byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, ".xz"}, // XZ
	{[]byte{0x25, 0x50, 0x44, 0x46}, ".pdf"},         // PDF
}

// Known binary extensions to skip without checking magic numbers
var binaryExtensions = map[string]struct{}{
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".bmp": {}, ".ico": {}, ".webp": {}, ".svg": {}, ".tiff": {},
	".mp4": {}, ".avi": {}, ".mov": {}, ".mkv": {}, ".webm": {}, ".mp3": {}, ".wav": {}, ".ogg": {}, ".flac": {},
	".zip": {}, ".tar": {}, ".gz": {}, ".rar": {}, ".7z": {}, ".bz2": {}, ".xz": {},
	".exe": {}, ".dll": {}, ".so": {}, ".dylib": {}, ".o": {}, ".obj": {},
	".pyc": {}, ".pyo": {}, ".class": {}, ".jar": {}, ".war": {},
	".woff": {}, ".woff2": {}, ".ttf": {}, ".eot": {}, ".otf": {},
	".wasm": {}, ".db": {}, ".sqlite": {}, ".sqlite3": {},
	".lock": {}, "lock": {}, // package-lock.json, Cargo.lock, etc.
}

// IsBinaryFile checks if a staged file is binary by extension or magic numbers.
// Reads only the first 6 bytes from the git stream — O(1) memory.
func IsBinaryFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	filename := strings.ToLower(filepath.Base(filePath))

	// Quick check by extension
	if _, ok := binaryExtensions[ext]; ok {
		return true
	}
	// Special case: lock files (package-lock.json, yarn.lock)
	if strings.HasSuffix(filename, "-lock.json") || strings.HasSuffix(filename, ".lock") || filename == "yarn.lock" || filename == "go.sum" || filename == "package-lock.json" {
		return true
	}

	// Check magic numbers — read first 6 bytes from staged content
	cmd := exec.Command("git", "show", ":"+filePath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false // If we can't check, assume text (safe default)
	}
	if err := cmd.Start(); err != nil {
		return false
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()

	buf := make([]byte, 6)
	n, err := stdout.Read(buf)
	if err != nil || n < 2 {
		return false // Too short to determine
	}
	header := buf[:n]

	for _, sig := range binarySignatures {
		if len(header) >= len(sig.magic) {
			if bytes.Equal(header[:len(sig.magic)], sig.magic) {
				return true
			}
		}
	}

	// Check for null bytes — strong indicator of binary content
	if bytes.Contains(header, []byte{0x00}) {
		return true
	}

	return false
}

// ============================================================
// Shannon entropy — O(1) memory via streaming frequency count
// ============================================================

// CalculateEntropy computes Shannon entropy of a string.
// Time: O(n), Space: O(unique chars) = O(1) bounded by charset size.
func CalculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	// Frequency map — bounded by charset size (ASCII = 256 max)
	freq := make(map[rune]int, 256)
	total := 0
	for _, ch := range s {
		freq[ch]++
		total++
	}

	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / float64(total)
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// ============================================================
// Obfuscation
// ============================================================

func ObfuscateSecret(secret string) string {
	if len(secret) <= 8 {
		if len(secret) < 4 {
			return secret
		}
		return secret[:2] + strings.Repeat("*", len(secret)-4) + secret[len(secret)-2:]
	}
	return secret[:4] + "..." + secret[len(secret)-4:]
}

// ============================================================
// Git integration
// ============================================================

func RunGitCommand(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %v: %w: %s", args, err, string(out))
	}
	return string(out), nil
}

func GetStagedFiles() ([]string, error) {
	out, err := RunGitCommand("diff", "--cached", "--name-only", "--diff-filter=ACMR")
	if err != nil {
		// No staged files is not an error
		if strings.TrimSpace(out) == "" {
			return nil, nil
		}
		return nil, err
	}

	var files []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}

// GetStagedFileReader returns a StagedScanner that reads staged file content
// line by line with constant memory — never loads full file into RAM.
func GetStagedFileReader(filePath string) (*StagedScanner, error) {
	cmd := exec.Command("git", "show", ":"+filePath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("creating pipe for %s: %w", filePath, err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting git show for %s: %w", filePath, err)
	}

	scanner := bufio.NewScanner(stdout)
	// Set initial buffer — scanner grows as needed but starts small
	scanner.Buffer(make([]byte, LineBufferSize), 1024*1024) // max 1MB line (practical limit)

	return &StagedScanner{
		Scanner: scanner,
		Cmd:     cmd,
		Done:    false,
	}, nil
}

// StagedScanner wraps scanner + git process for proper cleanup
type StagedScanner struct {
	*bufio.Scanner
	Cmd  *exec.Cmd
	Done bool
}

func (s *StagedScanner) Scan() bool {
	if s.Done {
		return false
	}
	if s.Scanner.Scan() {
		return true
	}
	s.Done = true
	// Process cleanup — non-blocking drain
	go func() {
		s.Cmd.Process.Kill()
		s.Cmd.Wait()
	}()
	return false
}

// ============================================================
// Config management
// ============================================================

func LoadConfig(repoRoot string) (*Config, error) {
	configPath := filepath.Join(repoRoot, ConfigFilename)
	cfg := &Config{
		EntropyThreshold: EntropyThreshold,
		MinSecretLength:  MinSecretLength,
		Severity:         SeverityBlock,
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // no config file = use defaults
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Validate severity
	if cfg.Severity != SeverityBlock && cfg.Severity != SeverityWarn {
		cfg.Severity = SeverityBlock // Default to block if invalid
	}

	// Pre-compile ignore regex patterns
	for _, pat := range cfg.IgnorePatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("compiling ignore pattern %q: %w", pat, err)
		}
		cfg.compiledIgnores = append(cfg.compiledIgnores, re)
	}

	// Pre-compile custom patterns
	for _, cp := range cfg.CustomPatterns {
		re, err := regexp.Compile(cp.Regex)
		if err != nil {
			return nil, fmt.Errorf("compiling custom pattern %q: %w", cp.Regex, err)
		}
		cfg.compiledCustoms = append(cfg.compiledCustoms, SecretPattern{
			Regex: re,
			Name:  cp.Name,
		})
	}

	return cfg, nil
}

var ignorePatternRE = regexp.MustCompile(`(?i)env-shield-ignore`)

func IsIgnoredLine(line string) bool {
	return ignorePatternRE.MatchString(line)
}

func IsIgnoredFile(fp string, cfg *Config) bool {
	if cfg == nil {
		return false
	}

	for _, ignored := range cfg.IgnoreFiles {
		if fp == ignored {
			return true
		}
	}

	for _, re := range cfg.compiledIgnores {
		if re.MatchString(fp) {
			return true
		}
	}

	return false
}

// ============================================================
// Detection Layer 1: Regex
// ============================================================

func DetectRegexSecrets(filePath, line string, lineNum int, cfg *Config) []Finding {
	if IsIgnoredLine(line) {
		return nil
	}

	severity := SeverityBlock
	if cfg != nil && cfg.Severity == SeverityWarn {
		severity = SeverityWarn
	}

	var findings []Finding

	// Built-in patterns
	for _, pattern := range SecretPatterns {
		matches := pattern.Regex.FindAllString(line, -1)
		for _, secret := range matches {
			findings = append(findings, Finding{
				File:     filePath,
				Line:     lineNum,
				Type:     pattern.Name,
				Secret:   secret,
				Layer:    "regex",
				Severity: severity,
			})
		}
	}

	// Custom patterns (from config)
	if cfg != nil {
		for _, pattern := range cfg.compiledCustoms {
			matches := pattern.Regex.FindAllString(line, -1)
			for _, secret := range matches {
				findings = append(findings, Finding{
					File:     filePath,
					Line:     lineNum,
					Type:     pattern.Name,
					Secret:   secret,
					Layer:    "custom",
					Severity: severity,
				})
			}
		}
	}

	return findings
}

// ============================================================
// Detection Layer 2: Shannon Entropy (streaming, constant memory)
// ============================================================

// Pre-compiled assignment patterns for entropy detection
var entropyAssignmentPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:api_key|apikey|secret|password|passwd|pwd|token|auth_token|access_token|key)\s*[:=]\s*["']?([A-Za-z0-9_\-+/]{16,})["']?`),
	regexp.MustCompile(`(?i)(?:export\s+)?(?:API_KEY|APIKEY|SECRET|PASSWORD|PASSWD|PWD|TOKEN|AUTH_TOKEN|ACCESS_TOKEN|KEY)\s*=?\s*["']?([A-Za-z0-9_\-+/]{16,})["']?`),
}

func DetectEntropySecrets(filePath, line string, lineNum int, threshold float64, minLen int, severity Severity) []Finding {
	if IsIgnoredLine(line) {
		return nil
	}

	var findings []Finding
	for _, pattern := range entropyAssignmentPatterns {
		matches := pattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			candidate := match[1]
			if len(candidate) < minLen {
				continue
			}
			entropy := CalculateEntropy(candidate)
			if entropy >= threshold {
				findings = append(findings, Finding{
					File:     filePath,
					Line:     lineNum,
					Type:     fmt.Sprintf("High Entropy String (entropy: %.2f)", entropy),
					Secret:   candidate,
					Layer:    "entropy",
					Severity: severity,
				})
			}
		}
	}
	return findings
}

// ============================================================
// Detection Layer 3: Forbidden files
// ============================================================

func DetectForbiddenFile(filePath string, severity Severity) []Finding {
	filename := filepath.Base(filePath)
	filenameLower := strings.ToLower(filename)
	ext := filepath.Ext(filePath)
	extLower := strings.ToLower(ext)

	var findings []Finding

	// Check exact filename
	if _, ok := ForbiddenFilenames[filenameLower]; ok {
		findings = append(findings, Finding{
			File:     filePath,
			Line:     0,
			Type:     "Forbidden File",
			Secret:   filename,
			Layer:    "forbidden_file",
			Severity: severity,
		})
		return findings // Skip content analysis
	}

	// Check extension
	if _, ok := ForbiddenExtensions[extLower]; ok {
		findings = append(findings, Finding{
			File:     filePath,
			Line:     0,
			Type:     fmt.Sprintf("Forbidden Extension (%s)", ext),
			Secret:   filename,
			Layer:    "forbidden_file",
			Severity: severity,
		})
	}

	return findings
}

// ============================================================
// Worker pool — concurrent file analysis
// ============================================================

type FileJob struct {
	Index int
	Path  string
}

type FileResult struct {
	Index        int
	Findings     []Finding
	FilesScanned int
	FilesSkipped int
	Err          error
}

// ScanStagedFiles uses a worker pool to analyze all staged files concurrently.
// Memory: O(1) per file — streams line by line, never loads full content.
// Returns ScanResult with findings, file counts, and timing.
func ScanStagedFiles(cfg *Config) (*ScanResult, error) {
	start := time.Now()

	stagedFiles, err := GetStagedFiles()
	if err != nil {
		return nil, fmt.Errorf("getting staged files: %w", err)
	}

	if len(stagedFiles) == 0 {
		return &ScanResult{}, nil
	}

	// Apply config overrides
	if cfg == nil {
		cfg = &Config{
			EntropyThreshold: EntropyThreshold,
			MinSecretLength:  MinSecretLength,
			Severity:         SeverityBlock,
		}
	}

	// Channel for distributing work
	numWorkers := MaxWorkers
	if len(stagedFiles) < numWorkers {
		numWorkers = len(stagedFiles)
	}

	jobs := make(chan FileJob, len(stagedFiles))
	results := make(chan FileResult, len(stagedFiles))

	// Launch workers
	for w := 0; w < numWorkers; w++ {
		go worker(jobs, results, cfg)
	}

	// Feed jobs
	for i, f := range stagedFiles {
		jobs <- FileJob{Index: i, Path: f}
	}
	close(jobs)

	// Collect results
	result := &ScanResult{
		Findings: make([]Finding, 0),
	}
	for i := 0; i < len(stagedFiles); i++ {
		fileResult := <-results
		if fileResult.Err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Warning: %v\n", fileResult.Err)
			continue
		}
		result.Findings = append(result.Findings, fileResult.Findings...)
		result.FilesScanned += fileResult.FilesScanned
		result.FilesSkipped += fileResult.FilesSkipped
	}

	result.Duration = time.Since(start)

	// Count by severity
	for _, f := range result.Findings {
		if f.Severity == SeverityBlock {
			result.BlockedCount++
		} else {
			result.WarnedCount++
		}
	}

	return result, nil
}

// worker processes file jobs from the jobs channel and sends results.
// Each worker streams file content line-by-line — O(1) memory per file.
func worker(jobs <-chan FileJob, results chan<- FileResult, cfg *Config) {
	for job := range jobs {
		findings, scanned, skipped, err := analyzeFile(job.Path, cfg)
		results <- FileResult{
			Index:        job.Index,
			Findings:     findings,
			FilesScanned: scanned,
			FilesSkipped: skipped,
			Err:          err,
		}
	}
}

// analyzeFile scans a single staged file using streaming (constant memory).
// Returns findings, files scanned count, files skipped count, and error.
func analyzeFile(filePath string, cfg *Config) ([]Finding, int, int, error) {
	// Skip binary files (images, executables, archives)
	if IsBinaryFile(filePath) {
		return nil, 0, 1, nil
	}

	// Layer 3: Check forbidden files first (fast path)
	severity := SeverityBlock
	if cfg != nil {
		severity = cfg.Severity
	}
	forbiddenFindings := DetectForbiddenFile(filePath, severity)
	if len(forbiddenFindings) > 0 {
		return forbiddenFindings, 0, 1, nil // Skip content for forbidden files
	}

	// Check if file is ignored by config
	if IsIgnoredFile(filePath, cfg) {
		return nil, 0, 1, nil
	}

	// Get streaming scanner for staged content
	scanner, err := GetStagedFileReader(filePath)
	if err != nil {
		return nil, 0, 1, err
	}

	var findings []Finding
	lineNum := 0

	// Stream line by line — memory is O(1) w.r.t. file size
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Layer 1: Regex detection
		findings = append(findings, DetectRegexSecrets(filePath, line, lineNum, cfg)...)

		// Layer 2: Entropy detection
		findings = append(findings, DetectEntropySecrets(filePath, line, lineNum, cfg.EntropyThreshold, cfg.MinSecretLength, severity)...)
	}

	return findings, 1, 0, nil
}
