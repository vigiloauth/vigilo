package types

import (
	"slices"
	"strings"
)

// Scope represents an OAuth 2.0 or OpenID Connect scope.
// Scopes define the level of access that a client is requesting.
type Scope string

const (
	// TokenIntrospectScope allows introspection of access tokens,
	// typically used by resource servers or internal services.
	TokenIntrospectScope Scope = "tokens:introspect"

	// TokenRevokeScope allows revocation of access or refresh tokens.
	// Used by clients or systems that need to invalidate tokens.
	TokenRevokeScope Scope = "tokens:revoke"

	// OpenIDScope is required for OpenID Connect authentication.
	// It indicates that the application intends to use OIDC for identity-related information.
	OpenIDScope Scope = "openid"

	// UserProfileScope grants access to basic profile information of the user.
	// This includes:
	//   - name
	//   - family name
	//   - given name
	//   - middle name
	//   - preferred username
	//   - profile URL
	//   - picture URL
	//   - website URL
	//   - gender
	//   - birthdate
	//   - timezone
	//   - locale
	//   - updated_at timestamp
	UserProfileScope Scope = "profile"

	// UserEmailScope grants access to the user's email information, including:
	//   - email address
	//   - email verified status
	UserEmailScope Scope = "email"

	// UserPhoneScope grants access to the user's phone number information, including:
	//   - phone number
	//   - phone number verified status
	UserPhoneScope Scope = "phone"

	// UserAddressScope grants access to the user's address information, including:
	//   - formatted address
	//   - street address
	//   - locality (e.g., city)
	//   - region (e.g., state or province)
	//   - postal code
	//   - country
	UserAddressScope Scope = "address"

	// UserOfflineAccessScope grants the client access to the user's information while they are offline.
	// Typically used to request a refresh token for long-lived access.
	UserOfflineAccessScope Scope = "offline_access"
)

// SupportedScopes defines the set of recognized and allowed scopes within the application.
// Keys are the supported scope values; values indicate support (true = supported).
var SupportedScopes = map[Scope]bool{
	TokenIntrospectScope:   true,
	TokenRevokeScope:       true,
	OpenIDScope:            true,
	UserProfileScope:       true,
	UserEmailScope:         true,
	UserPhoneScope:         true,
	UserAddressScope:       true,
	UserOfflineAccessScope: true,
}

func (s Scope) String() string {
	return string(s)
}

// ParseScopesString converts a space-delimited scope string into a slice of Scope types
func ParseScopesString(scopeStr string) []Scope {
	if scopeStr == "" {
		return []Scope{}
	}

	parts := strings.Split(scopeStr, " ")
	scopes := make([]Scope, len(parts))

	for i, part := range parts {
		scopes[i] = Scope(part) // Or however you convert string to Scope
	}

	return scopes
}

// ContainsScope checks if a scope is in a slice of scopes
func ContainsScope(scopes []Scope, target Scope) bool {
	return slices.Contains(scopes, target)
}

// NewScopeList creates a single Scope value from multiple Scope values
func NewScopeList(scopes ...Scope) Scope {
	var combined strings.Builder
	for i, scope := range scopes {
		if i > 0 {
			combined.WriteString(" ")
		}
		combined.WriteString(scope.String())
	}
	return Scope(combined.String())
}

// CombineScopes combines multiple Scope values into a single Scope
func CombineScopes(scopes ...Scope) Scope {
	if len(scopes) == 0 {
		return Scope("")
	}

	var combined strings.Builder

	for i, scope := range scopes {
		if i > 0 {
			combined.WriteString(" ")
		}
		combined.WriteString(scope.String())
	}

	return Scope(combined.String())
}
