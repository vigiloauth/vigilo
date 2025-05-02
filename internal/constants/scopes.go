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

	// OpenIDScope Scopes
	OpenIDScope            string = "openid"         // OpenID Connect scope for basic OIDC functionality.
	UserProfileScope       string = "profile"        // Access to user profile (`name`, `middle_name`, `family_name`, `birthdate`, and `updated_at`).
	UserEmailScope         string = "email"          // Access to the user's email address (`email` and `email_verified`).
	UserPhoneScope         string = "phone"          // Access to the user's phone number (`phone_number` and `phone_number_verified`).
	UserAddressScope       string = "address"        // Access to the user's address.
	UserOfflineAccessScope string = "offline_access" // Access to the user's information while they are offline.
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
