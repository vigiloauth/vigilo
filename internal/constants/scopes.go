package constants

// Scopes define the permissions and access levels granted to clients and users
// in the OAuth 2.0 and OpenID Connect protocols. These constants represent
// the supported scopes in the application.
const (
	// Client Management Scopes
	ClientReadScope   string = "clients:read"   // Read registered client details.
	ClientWriteScope  string = "clients:write"  // Modify client details (except 'client_id' & 'client_secret').
	ClientDeleteScope string = "clients:delete" // Delete a registered client.
	ClientManageScope string = "clients:manage" // Full control over all clients (includes 'read', 'write', and 'delete').

	// Token Management Scopes
	TokenIntrospectScope string = "tokens:introspect" // Introspect tokens to retrieve metadata.
	TokenRevokeScope     string = "tokens:revoke"     // Revoke tokens to invalidate them.

	// User Management Scopes
	UserReadScope   string = "users:read"   // Read user details (e.g., profile, email, etc.).
	UserWriteScope  string = "users:write"  // Modify user details.
	UserDeleteScope string = "users:delete" // Delete a user account.
	UserManageScope string = "users:manage" // Full control over users ('read', 'write', and 'delete').

	// OpenID Connect scope for basic OIDC functionality.
	OpenIDScope string = "openid"

	// Access to the user's profile information which includes:
	//	- name
	//	- family name
	//	- given name
	//	- middle name
	//	- preferred username
	//	- profile
	//	- picture
	//	- website
	//	- gender
	//	- birthdate
	//	- time zone information
	//	- locale
	//	- update at
	UserProfileScope string = "profile"

	// Access to the user's email information which includes:
	//	- email address
	//	- email verified
	UserEmailScope string = "email"

	// Access to the user's phone information which includes:
	//	- phone number
	//	- phone number verified
	UserPhoneScope string = "phone"

	// Access to the user's address which includes:
	//	- formatted
	//	- street address
	//	- locality
	//	- region
	//	- postal code
	//	- country
	UserAddressScope string = "address"

	// Access to the user's information while they are offline.
	UserOfflineAccessScope string = "offline_access"
)

// SupportedScopes is a map of scopes supported by the application.
// The key is the scope, and the value indicates whether it is supported.
var SupportedScopes = map[string]bool{
	ClientReadScope:   true,
	ClientWriteScope:  true,
	ClientDeleteScope: true,
	ClientManageScope: true,

	TokenIntrospectScope: true,
	TokenRevokeScope:     true,

	UserManageScope:        true,
	UserReadScope:          true,
	UserDeleteScope:        true,
	UserWriteScope:         true,
	OpenIDScope:            true,
	UserProfileScope:       true,
	UserEmailScope:         true,
	UserPhoneScope:         true,
	UserAddressScope:       true,
	UserOfflineAccessScope: true,
}
