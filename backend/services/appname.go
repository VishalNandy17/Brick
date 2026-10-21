package services

import (
	"regexp"
	"strings"
)

// SanitizeAppName cleans an email or string into a usable default app name.
// e.g. "john.doe@gmail.com" → "My Application"
func SanitizeAppName(input string) string {
	// Strip domain from email
	if idx := strings.Index(input, "@"); idx > 0 {
		input = input[:idx]
	}
	// Replace dots, underscores, dashes with spaces
	re := regexp.MustCompile(`[._\-]+`)
	input = re.ReplaceAllString(input, " ")
	// Title case each word
	words := strings.Fields(input)
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(string(w[0])) + strings.ToLower(w[1:])
		}
	}
	result := strings.Join(words, " ")
	if result == "" {
		return "My Application"
	}
	return result + "'s App"
}
