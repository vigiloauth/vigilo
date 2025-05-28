package utils

import (
	"net/url"
)

// TruncateSensitive shortens sensitive strings for safe logging.
//
// Parameters:
//   - data string: The sensitive string to truncate.
//
// Returns:
//   - string: A truncated version of the string with "[REDACTED]" appended if its length
//     is greater than 5. Otherwise, returns the original string.
func TruncateSensitive(data string) string {
	const minDataLength int = 5
	if len(data) > minDataLength {
		return data[:minDataLength] + "[REDACTED]"
	}

	return data
}

// SanitizeURL redacts query parameters from the provided URL for secure logging.
//
// Parameters:
//   - uri string: The URL string to sanitize.
//
// Returns:
//   - string: The sanitized URL with query parameters replaced by "[REDACTED]".
//     If the URL is invalid, returns "[INVALID URL]".
func SanitizeURL(uri string) string {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "[INVALID URL]"
	}

	parsed.RawQuery = "[REDACTED]"
	return parsed.String()
}
