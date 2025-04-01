package common

import "net/url"

// Helper function to truncate sensitive data for logging
func TruncateSensitive(data string) string {
	if len(data) > 5 {
		return data[:5] + "..."
	}
	return data
}

// Helper function to sanitize URLs for logging
func SanitizeURL(uri string) string {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "[INVALID URL]"
	}
	parsed.RawQuery = "[REDACTED]"
	return parsed.String()
}
