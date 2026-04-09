package core

import (
	"fmt"
	"strings"
)

// FormatFindings produces a human-readable report of detected secrets.
func FormatFindings(findings []Finding) string {
	if len(findings) == 0 {
		return ""
	}

	var b strings.Builder
	sep := strings.Repeat("=", 60)

	b.WriteString("\n")
	b.WriteString(sep + "\n")
	b.WriteString("  🛡️  Env-Shield: SECRETS DETECTED!\n")
	b.WriteString(sep + "\n")
	b.WriteString(fmt.Sprintf("  Found %d potential secret(s) in staged files.\n", len(findings)))
	b.WriteString("  Commit BLOCKED to prevent credential leakage.\n")
	b.WriteString(sep + "\n")

	for i, f := range findings {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  [%d] File: %s\n", i+1, f.File))
		if f.Line > 0 {
			b.WriteString(fmt.Sprintf("      Line: %d\n", f.Line))
		} else {
			b.WriteString("      Line: N/A\n")
		}
		b.WriteString(fmt.Sprintf("      Type: %s\n", f.Type))
		b.WriteString(fmt.Sprintf("      Layer: %s\n", f.Layer))
		b.WriteString(fmt.Sprintf("      Value: %s\n", ObfuscateSecret(f.Secret)))
	}

	b.WriteString("\n" + sep + "\n")
	b.WriteString("  💡 To bypass, add \"// env-shield-ignore\" to the line\n")
	b.WriteString("     or add the file to \".env-shield.json\" ignore list.\n")
	b.WriteString(sep + "\n")

	return b.String()
}
