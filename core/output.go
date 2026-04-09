package core

import (
	"fmt"
	"strings"
	"time"
)

// FormatFindings produces a human-readable report of detected secrets with performance metrics.
func FormatFindings(result *ScanResult) string {
	if len(result.Findings) == 0 {
		return fmt.Sprintf("✅ Env-Shield: No secrets detected. (scanned %d files in %s)\n",
			result.FilesScanned, result.Duration.Round(time.Millisecond))
	}

	var b strings.Builder
	sep := strings.Repeat("=", 60)

	b.WriteString("\n")
	b.WriteString(sep + "\n")
	b.WriteString("  🛡️  Env-Shield: SECRETS DETECTED!\n")
	b.WriteString(sep + "\n")
	b.WriteString(fmt.Sprintf("  Found %d potential secret(s) in %d staged file(s).\n",
		len(result.Findings), result.FilesScanned))

	// Summary by severity
	if result.BlockedCount > 0 {
		b.WriteString(fmt.Sprintf("  🚫 %d finding(s) BLOCK commit.\n", result.BlockedCount))
	}
	if result.WarnedCount > 0 {
		b.WriteString(fmt.Sprintf("  ⚠️  %d finding(s) are warnings (severity: warn).\n", result.WarnedCount))
	}

	b.WriteString(fmt.Sprintf("  ⏱️  Scan time: %s | Files skipped (binary/ignored): %d\n",
		result.Duration.Round(time.Millisecond), result.FilesSkipped))
	b.WriteString(sep + "\n")

	for i, f := range result.Findings {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  [%d] File: %s\n", i+1, f.File))
		if f.Line > 0 {
			b.WriteString(fmt.Sprintf("      Line: %d\n", f.Line))
		} else {
			b.WriteString("      Line: N/A\n")
		}
		b.WriteString(fmt.Sprintf("      Type: %s\n", f.Type))
		b.WriteString(fmt.Sprintf("      Layer: %s\n", f.Layer))
		b.WriteString(fmt.Sprintf("      Severity: %s\n", f.Severity))
		b.WriteString(fmt.Sprintf("      Value: %s\n", ObfuscateSecret(f.Secret)))
	}

	b.WriteString("\n" + sep + "\n")
	b.WriteString("  💡 To bypass, add \"// env-shield-ignore\" to the line\n")
	b.WriteString("     or add the file to \".env-shield.json\" ignore list.\n")
	b.WriteString(sep + "\n")

	return b.String()
}
