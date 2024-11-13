/*
 * Copyright 2024 Olivier Pimpare-Charbonneau, Zachary Sexton
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package utils

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

func ValidateURLPattern(url *string) error {
	uriPattern := regexp.MustCompile(`^(?:http|https)://[\w\-.]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[\w\-./]*)?(?:\?[\w\-=&]*)?$`)
	if !uriPattern.MatchString(*url) {
		return fmt.Errorf("malformed URL: must be a valid URL with standard characters")
	}
	return nil
}

func ValidateAgainstInvalidChars(url *string) error {
	invalidChars := []string{"<", ">", "'", "\"", ";", "%", "\\", "{", "}", "|", "^", "~", "[", "]", "`"}
	for _, char := range invalidChars {
		if strings.Contains(*url, char) {
			return fmt.Errorf("malformed URL: contains invalid character '%s'", char)
		}
	}
	return nil
}

func ValidateHost(url *string) error {
	hostParts := strings.Split(*url, ":")
	if len(hostParts) < 2 {
		return fmt.Errorf("malformed URL: invalid hostname format")
	}

	if net.ParseIP(*url) != nil {
		return fmt.Errorf("malformed URL: IP addresses are not allowed")
	}

	return nil
}
