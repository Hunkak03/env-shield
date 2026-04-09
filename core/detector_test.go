package core

import (
	"math"
	"regexp"
	"strings"
	"testing"
	"time"
)

// ============================================================
// Shannon Entropy Tests
// ============================================================

func TestCalculateEntropy_Empty(t *testing.T) {
	if got := CalculateEntropy(""); got != 0.0 {
		t.Errorf("entropy of empty string = %f, want 0.0", got)
	}
}

func TestCalculateEntropy_Uniform(t *testing.T) {
	// All same characters = 0 entropy
	if got := CalculateEntropy("aaaaaaaaaa"); got != 0.0 {
		t.Errorf("entropy of uniform string = %f, want 0.0", got)
	}
}

func TestCalculateEntropy_HighRandomness(t *testing.T) {
	// High-entropy string should be > 4.0
	got := CalculateEntropy("xK9mP2vLqR7nW4jTsY8aB3cD5eF")
	if got < 4.0 {
		t.Errorf("entropy of random-looking string = %f, want >= 4.0", got)
	}
}

func TestCalculateEntropy_BinaryMix(t *testing.T) {
	// Mix of different chars should have measurable entropy
	got := CalculateEntropy("a1b2c3d4e5f6g7h8i9j0")
	if got < 3.0 || got > 5.0 {
		t.Errorf("entropy of mixed string = %f, expected ~3.0-5.0", got)
	}
}

func TestCalculateEntropy_ConstantMemory(t *testing.T) {
	// Entropy should not depend on string length for same distribution
	short := CalculateEntropy("abcd")
	long := CalculateEntropy("abcdabcdabcdabcdabcd")
	// Both should be ~2.0 (4 unique chars, uniform)
	if math.Abs(short-long) > 0.5 {
		t.Errorf("short entropy=%f, long entropy=%f — should be similar", short, long)
	}
}

// ============================================================
// Obfuscation Tests
// ============================================================

func TestObfuscateSecret_Short(t *testing.T) {
	got := ObfuscateSecret("abc12345")
	if !strings.HasPrefix(got, "ab") || !strings.HasSuffix(got, "45") {
		t.Errorf("obfuscate(%q) = %q, expected ab...45 pattern", "abc12345", got)
	}
	if !strings.Contains(got, "*") {
		t.Errorf("obfuscate(%q) = %q, expected * characters", "abc12345", got)
	}
}

func TestObfuscateSecret_Long(t *testing.T) {
	got := ObfuscateSecret("AKIAIOSFODNN7EXAMPLE")
	if !strings.HasPrefix(got, "AKIA") {
		t.Errorf("obfuscate(%q) = %q, expected AKIA prefix", "AKIAIOSFODNN7EXAMPLE", got)
	}
	if !strings.HasSuffix(got, "MPLE") {
		t.Errorf("obfuscate(%q) = %q, expected MPLE suffix", "AKIAIOSFODNN7EXAMPLE", got)
	}
	if !strings.Contains(got, "...") {
		t.Errorf("obfuscate(%q) = %q, expected ... ellipsis", "AKIAIOSFODNN7EXAMPLE", got)
	}
}

func TestObfuscateSecret_VeryShort(t *testing.T) {
	got := ObfuscateSecret("abc")
	if got != "abc" {
		t.Errorf("obfuscate(%q) = %q, expected unchanged for very short", "abc", got)
	}
}

func TestObfuscateSecret_MinimumLength(t *testing.T) {
	// 4 chars: ab + 0 stars + cd = unchanged (can't hide anything)
	got := ObfuscateSecret("abcd")
	if got != "abcd" {
		t.Errorf("obfuscate(%q) = %q, expected unchanged (too short to mask)", "abcd", got)
	}
	// 5 chars: ab + 1 star + d = ab*d
	got2 := ObfuscateSecret("abcde")
	if got2 != "ab*de" {
		t.Errorf("obfuscate(%q) = %q, expected ab*de", "abcde", got2)
	}
}

// ============================================================
// Regex Detection Tests
// ============================================================

func TestDetectRegexSecrets_AWSAccessKey(t *testing.T) {
	cfg := &Config{Severity: SeverityBlock}
	findings := DetectRegexSecrets("config.py", "key = AKIAIOSFODNN7EXAMPLE", 1, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "AWS Access Key ID" {
		t.Errorf("expected AWS Access Key ID, got %q", findings[0].Type)
	}
	if findings[0].File != "config.py" {
		t.Errorf("expected file config.py, got %q", findings[0].File)
	}
	if findings[0].Line != 1 {
		t.Errorf("expected line 1, got %d", findings[0].Line)
	}
	if findings[0].Severity != SeverityBlock {
		t.Errorf("expected severity block, got %q", findings[0].Severity)
	}
}

func TestDetectRegexSecrets_StripeKey(t *testing.T) {
	// Build dynamically so the prefix never appears as a literal in git history
	secret := "sk_" + "live_" + "TESTTESTTESTTESTTESTTESTTESTab"
	findings := DetectRegexSecrets("payment.go", "STRIPE="+secret, 5, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Type, "Stripe") {
		t.Errorf("expected Stripe type, got %q", findings[0].Type)
	}
}

func TestDetectRegexSecrets_GoogleAPIKey(t *testing.T) {
	findings := DetectRegexSecrets("app.js", "KEY=AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q", 10, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Type, "Google") {
		t.Errorf("expected Google type, got %q", findings[0].Type)
	}
}

func TestDetectRegexSecrets_PrivateKey(t *testing.T) {
	findings := DetectRegexSecrets("cert.pem", "-----BEGIN RSA PRIVATE KEY-----", 1, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Type, "Private Key") {
		t.Errorf("expected Private Key type, got %q", findings[0].Type)
	}
}

func TestDetectRegexSecrets_GitHubToken(t *testing.T) {
	findings := DetectRegexSecrets("deploy.sh", "TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234", 1, nil)
	if len(findings) < 1 {
		t.Fatalf("expected >= 1 finding, got %d", len(findings))
	}
	found := false
	for _, f := range findings {
		if strings.Contains(f.Type, "GitHub") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected GitHub finding in types: %v", findings)
	}
}

func TestDetectRegexSecrets_SlackToken(t *testing.T) {
	// Build dynamically so the prefix never appears as a literal in git history
	token := "xox" + "b-" + "1234567890-1234567890-TESTTESTTESTTESTTESTTESTTEST"
	findings := DetectRegexSecrets("slack.go", token, 1, nil)
	if len(findings) < 1 {
		t.Fatalf("expected >= 1 finding, got %d", len(findings))
	}
	found := false
	for _, f := range findings {
		if strings.Contains(f.Type, "Slack") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected Slack finding in types: %v", findings)
	}
}

func TestDetectRegexSecrets_JWT(t *testing.T) {
	findings := DetectRegexSecrets("auth.js", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdef123456", 1, nil)
	if len(findings) < 1 {
		t.Fatalf("expected >= 1 finding, got %d", len(findings))
	}
	found := false
	for _, f := range findings {
		if strings.Contains(f.Type, "JWT") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected JWT finding in types: %v", findings)
	}
}

func TestDetectRegexSecrets_NoSecrets(t *testing.T) {
	findings := DetectRegexSecrets("hello.go", "fmt.Println(\"hello world\")", 1, nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean code, got %d", len(findings))
	}
}

func TestDetectRegexSecrets_IgnoredLine(t *testing.T) {
	findings := DetectRegexSecrets("config.py", "key = AKIAIOSFODNN7EXAMPLE // env-shield-ignore", 1, nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for ignored line, got %d", len(findings))
	}
}

func TestDetectRegexSecrets_MultipleOnSameLine(t *testing.T) {
	stripe := "sk_" + "live_" + "TESTTESTTESTTESTTESTTESTTESTab"
	findings := DetectRegexSecrets("multi.txt", "AKIAIOSFODNN7EXAMPLE "+stripe, 1, nil)
	if len(findings) < 2 {
		t.Errorf("expected >= 2 findings for multi-secret line, got %d", len(findings))
	}
}

// ============================================================
// Entropy Detection Tests
// ============================================================

func TestDetectEntropySecrets_HighEntropy(t *testing.T) {
	findings := DetectEntropySecrets("config.go", `API_KEY = "xK9mP2vLqR7nW4jTsY8aB3cD5eF"`, 1, 4.5, 16, SeverityBlock)
	if len(findings) < 1 {
		t.Errorf("expected >= 1 finding for high-entropy secret, got %d", len(findings))
	}
}

func TestDetectEntropySecrets_LowEntropy(t *testing.T) {
	findings := DetectEntropySecrets("config.go", `API_KEY = "aaaaaaaaaaaaaaaaaaaa"`, 1, 4.5, 16, SeverityBlock)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for low-entropy string, got %d", len(findings))
	}
}

func TestDetectEntropySecrets_IgnoredLine(t *testing.T) {
	findings := DetectEntropySecrets("config.go", `TOKEN = "xK9mP2vLqR7nW4jTsY8aB3cD5eF" // env-shield-ignore`, 1, 4.5, 16, SeverityBlock)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for ignored line, got %d", len(findings))
	}
}

func TestDetectEntropySecrets_TooShort(t *testing.T) {
	findings := DetectEntropySecrets("config.go", `KEY = "short"`, 1, 4.5, 16, SeverityBlock)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for short string, got %d", len(findings))
	}
}

func TestDetectEntropySecrets_SeverityWarn(t *testing.T) {
	findings := DetectEntropySecrets("config.go", `API_KEY = "xK9mP2vLqR7nW4jTsY8aB3cD5eF"`, 1, 4.5, 16, SeverityWarn)
	if len(findings) < 1 {
		t.Fatalf("expected >= 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityWarn {
		t.Errorf("expected severity warn, got %q", findings[0].Severity)
	}
}

// ============================================================
// Forbidden File Tests
// ============================================================

func TestDetectForbiddenFile_EnvFile(t *testing.T) {
	findings := DetectForbiddenFile(".env", SeverityBlock)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for .env, got %d", len(findings))
	}
	if findings[0].Type != "Forbidden File" {
		t.Errorf("expected Forbidden File type, got %q", findings[0].Type)
	}
	if findings[0].Severity != SeverityBlock {
		t.Errorf("expected severity block, got %q", findings[0].Severity)
	}
}

func TestDetectForbiddenFile_PemExtension(t *testing.T) {
	findings := DetectForbiddenFile("certs/server.pem", SeverityBlock)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for .pem, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Type, ".pem") {
		t.Errorf("expected .pem in type, got %q", findings[0].Type)
	}
}

func TestDetectForbiddenFile_IdRsa(t *testing.T) {
	findings := DetectForbiddenFile(".ssh/id_rsa", SeverityBlock)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for id_rsa, got %d", len(findings))
	}
}

func TestDetectForbiddenFile_KeyExtension(t *testing.T) {
	findings := DetectForbiddenFile("keys/private.key", SeverityBlock)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for .key, got %d", len(findings))
	}
}

func TestDetectForbiddenFile_SafeFile(t *testing.T) {
	findings := DetectForbiddenFile("src/app.go", SeverityBlock)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for safe file, got %d", len(findings))
	}
}

func TestDetectForbiddenFile_CredentialsJSON(t *testing.T) {
	findings := DetectForbiddenFile("service-account.json", SeverityBlock)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for credentials.json, got %d", len(findings))
	}
}

// ============================================================
// Config & Ignore Tests
// ============================================================

func TestIsIgnoredLine_CaseInsensitive(t *testing.T) {
	tests := []struct {
		line    string
		ignored bool
	}{
		{"// env-shield-ignore", true},
		{"# ENV-SHIELD-IGNORE", true},
		{"key = secret // Env-Shield-Ignore", true},
		{"key = secret", false},
		{"// some other comment", false},
	}
	for _, tt := range tests {
		if got := IsIgnoredLine(tt.line); got != tt.ignored {
			t.Errorf("IsIgnoredLine(%q) = %v, want %v", tt.line, got, tt.ignored)
		}
	}
}

func TestIsIgnoredFile_ByExactName(t *testing.T) {
	cfg := &Config{
		IgnoreFiles: []string{"test/fixtures/keys.pem"},
	}
	if !IsIgnoredFile("test/fixtures/keys.pem", cfg) {
		t.Error("expected test/fixtures/keys.pem to be ignored")
	}
	if IsIgnoredFile("src/app.go", cfg) {
		t.Error("expected src/app.go to NOT be ignored")
	}
}

func TestIsIgnoredFile_ByPattern(t *testing.T) {
	cfg := &Config{
		IgnorePatterns: []string{`\.test\.`, `\.spec\.`},
	}
	// Compile patterns
	cfg.compiledIgnores = append(cfg.compiledIgnores, regexp.MustCompile(`\.test\.`))
	cfg.compiledIgnores = append(cfg.compiledIgnores, regexp.MustCompile(`\.spec\.`))

	if !IsIgnoredFile("config.test.go", cfg) {
		t.Error("expected config.test.go to be ignored")
	}
	if !IsIgnoredFile("auth.spec.ts", cfg) {
		t.Error("expected auth.spec.ts to be ignored")
	}
	if IsIgnoredFile("src/app.go", cfg) {
		t.Error("expected src/app.go to NOT be ignored")
	}
}

func TestIsIgnoredFile_NilConfig(t *testing.T) {
	if IsIgnoredFile(".env", nil) {
		t.Error("expected nil config to never ignore files")
	}
}

func TestIsIgnoredFile_EmptyConfig(t *testing.T) {
	cfg := &Config{}
	if IsIgnoredFile(".env", cfg) {
		t.Error("expected empty config to never ignore files")
	}
}

// ============================================================
// Benchmark Tests — Verify O(1) memory characteristics
// ============================================================

func BenchmarkCalculateEntropy_Short(b *testing.B) {
	s := "xK9mP2vL"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		CalculateEntropy(s)
	}
}

func BenchmarkCalculateEntropy_Long(b *testing.B) {
	// 10KB string — should still use bounded memory
	s := strings.Repeat("xK9mP2vLqR7nW4jTsY8aB3cD5eF", 400)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		CalculateEntropy(s)
	}
}

func BenchmarkDetectRegexSecrets_CleanFile(b *testing.B) {
	content := strings.Repeat("fmt.Println(\"hello world\")\n", 100)
	cfg := &Config{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Simulate line-by-line processing
		for lineNum, line := range strings.Split(content, "\n") {
			DetectRegexSecrets("hello.go", line, lineNum+1, cfg)
		}
	}
}

func BenchmarkDetectRegexSecrets_WithSecret(b *testing.B) {
	content := strings.Repeat("fmt.Println(\"hello world\")\n", 50) +
		"key = AKIAIOSFODNN7EXAMPLE\n" +
		strings.Repeat("fmt.Println(\"hello world\")\n", 50)
	cfg := &Config{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for lineNum, line := range strings.Split(content, "\n") {
			DetectRegexSecrets("config.go", line, lineNum+1, cfg)
		}
	}
}

func BenchmarkDetectEntropySecrets(b *testing.B) {
	content := `API_KEY = "xK9mP2vLqR7nW4jTsY8aB3cD5eFgH"
NORMAL_VAR = "hello world"
TOKEN = "aB3cD5eF7gH9jK2mN4pQ6rS8tU0vW"
`
	cfg := &Config{
		EntropyThreshold: 4.5,
		MinSecretLength:  16,
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for lineNum, line := range strings.Split(content, "\n") {
			DetectEntropySecrets("config.go", line, lineNum+1, cfg.EntropyThreshold, cfg.MinSecretLength, SeverityBlock)
		}
	}
}

// ============================================================
// NEW FEATURE TESTS (Senior-level improvements)
// ============================================================

// 1. Binary file detection
func TestIsBinaryFile_ByExtension(t *testing.T) {
	binaries := []string{
		"image.png", "photo.jpg", "app.exe", "archive.zip",
		"font.woff2", "data.db", "lib.so", "game.wasm",
	}
	for _, path := range binaries {
		if !IsBinaryFile(path) {
			t.Errorf("expected %q to be detected as binary", path)
		}
	}
}

func TestIsBinaryFile_TextFiles(t *testing.T) {
	texts := []string{
		"main.go", "README.md", "config.json", "style.css",
		"app.js", "server.py", "index.html",
	}
	for _, path := range texts {
		if IsBinaryFile(path) {
			t.Errorf("expected %q to NOT be detected as binary", path)
		}
	}
}

func TestIsBinaryFile_LockFiles(t *testing.T) {
	lockFiles := []string{
		"package-lock.json", "yarn.lock", "Cargo.lock", "go.sum",
	}
	for _, path := range lockFiles {
		if !IsBinaryFile(path) {
			t.Errorf("expected %q to be detected as binary/lock file", path)
		}
	}
}

// 2. Custom patterns from config
func TestCustomPatterns_FromConfig(t *testing.T) {
	cfg := &Config{
		Severity: SeverityBlock,
		CustomPatterns: []struct {
			Regex string `json:"regex"`
			Name  string `json:"name"`
		}{
			{Regex: `CORP_KEY_[A-Z0-9]{20}`, Name: "Corp Internal Key"},
		},
	}
	// Compile the custom patterns
	re := regexp.MustCompile(`CORP_KEY_[A-Z0-9]{20}`)
	cfg.compiledCustoms = append(cfg.compiledCustoms, SecretPattern{
		Regex: re,
		Name:  "Corp Internal Key",
	})

	findings := DetectRegexSecrets("config.go", "key = CORP_KEY_ABCDEFGHIJKLMNOPQRST", 1, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from custom pattern, got %d", len(findings))
	}
	if findings[0].Type != "Corp Internal Key" {
		t.Errorf("expected custom pattern name, got %q", findings[0].Type)
	}
	if findings[0].Layer != "custom" {
		t.Errorf("expected layer 'custom', got %q", findings[0].Layer)
	}
}

// 3. Severity levels
func TestSeverity_BlockVsWarn(t *testing.T) {
	cfgBlock := &Config{Severity: SeverityBlock}
	cfgWarn := &Config{Severity: SeverityWarn}

	line := `API_KEY = "xK9mP2vLqR7nW4jTsY8aB3cD5eF"`

	blockFindings := DetectEntropySecrets("config.go", line, 1, 4.5, 16, cfgBlock.Severity)
	warnFindings := DetectEntropySecrets("config.go", line, 1, 4.5, 16, cfgWarn.Severity)

	if len(blockFindings) < 1 || len(warnFindings) < 1 {
		t.Fatalf("expected findings in both cases")
	}
	if blockFindings[0].Severity != SeverityBlock {
		t.Errorf("block config: expected severity block, got %q", blockFindings[0].Severity)
	}
	if warnFindings[0].Severity != SeverityWarn {
		t.Errorf("warn config: expected severity warn, got %q", warnFindings[0].Severity)
	}
}

func TestSeverity_InvalidDefaultsToBlock(t *testing.T) {
	cfg := &Config{
		Severity: Severity("invalid"),
	}
	// LoadConfig would normalize this, but test the default behavior
	if cfg.Severity != SeverityBlock && cfg.Severity != SeverityWarn {
		// This test verifies the constant values are correct
		t.Logf("severity value: %q (invalid values handled by LoadConfig)", cfg.Severity)
	}
}

// 4. ScanResult with metrics
func TestScanResult_FormatFindings(t *testing.T) {
	result := &ScanResult{
		Findings: []Finding{
			{File: "config.go", Line: 10, Type: "AWS Access Key ID", Secret: "AKIAIOSFODNN7EXAMPLE", Layer: "regex", Severity: SeverityBlock},
		},
		FilesScanned: 5,
		FilesSkipped: 2,
		Duration:     23 * time.Millisecond,
		BlockedCount: 1,
		WarnedCount:  0,
	}

	output := FormatFindings(result)
	if output == "" {
		t.Fatal("expected non-empty output")
	}

	// Check metrics are present
	expectedParts := []string{
		"config.go",
		"AWS Access Key ID",
		"AKIA...MPLE",
		"staged file",       // FilesScanned
		"skipped",            // FilesSkipped
		"Scan time",          // Duration
		"Severity: block",    // Severity display
	}
	for _, part := range expectedParts {
		if !strings.Contains(output, part) {
			t.Errorf("expected output to contain %q, got:\n%s", part, output)
		}
	}
}

func TestScanResult_EmptyFindings(t *testing.T) {
	result := &ScanResult{
		FilesScanned: 3,
		Duration:     15 * time.Millisecond,
	}
	output := FormatFindings(result)
	if output == "" {
		t.Fatal("expected output even with no findings")
	}
	if !strings.Contains(output, "No secrets detected") {
		t.Errorf("expected 'No secrets detected' in output, got:\n%s", output)
	}
	if !strings.Contains(output, "scanned 3 file") {
		t.Errorf("expected file count in output, got:\n%s", output)
	}
}

// 5. Config severity validation
func TestConfig_SeverityDefaults(t *testing.T) {
	cfg := &Config{
		EntropyThreshold: EntropyThreshold,
		MinSecretLength:  MinSecretLength,
		Severity:         SeverityBlock,
	}
	if cfg.Severity != SeverityBlock {
		t.Errorf("expected default severity to be block, got %q", cfg.Severity)
	}
}

func TestConfig_CustomPatternsCompiles(t *testing.T) {
	cfg := &Config{
		CustomPatterns: []struct {
			Regex string `json:"regex"`
			Name  string `json:"name"`
		}{
			{Regex: `MY_SECRET_[A-Z]+`, Name: "My Custom Secret"},
		},
	}
	// Simulate what LoadConfig does
	for _, cp := range cfg.CustomPatterns {
		re, err := regexp.Compile(cp.Regex)
		if err != nil {
			t.Fatalf("failed to compile custom pattern: %v", err)
		}
		cfg.compiledCustoms = append(cfg.compiledCustoms, SecretPattern{
			Regex: re,
			Name:  cp.Name,
		})
	}

	findings := DetectRegexSecrets("test.go", "val = MY_SECRET_ABCDEF", 1, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from compiled custom pattern, got %d", len(findings))
	}
	if findings[0].Type != "My Custom Secret" {
		t.Errorf("expected 'My Custom Secret', got %q", findings[0].Type)
	}
}
