package constants

// Scopes define the permissions and access levels granted to clients and users
// in the OAuth 2.0 and OpenID Connect protocols. These constants represent
// the supported scopes in the application.
const (
	// Client Management Scopes
	ClientRead   string = "clients:read"   // Read registered client details.
	ClientWrite  string = "clients:write"  // Modify client details (except 'client_id' & 'client_secret').
	ClientDelete string = "clients:delete" // Delete a registered client.
	ClientManage string = "clients:manage" // Full control over all clients (includes 'read', 'write', and 'delete').

	// Token Management Scopes
	TokenIntrospect string = "tokens:introspect" // Introspect tokens to retrieve metadata.
	TokenRevoke     string = "tokens:revoke"     // Revoke tokens to invalidate them.

	// User Management Scopes
	UserRead   string = "users:read"   // Read user details (e.g., profile, email, etc.).
	UserWrite  string = "users:write"  // Modify user details.
	UserDelete string = "users:delete" // Delete a user account.
	UserManage string = "users:manage" // Full control over users ('read', 'write', and 'delete').

	// OIDC Scopes
	OIDC              string = "oidc"           // OpenID Connect scope for basic OIDC functionality.
	UserProfile       string = "profile"        // Access to user profile (`name`, `middle_name`, `family_name`, `birthdate`, and `updated_at`).
	UserEmail         string = "email"          // Access to the user's email address (`email` and `email_verified`).
	UserPhone         string = "phone"          // Access to the user's phone number (`phone_number` and `phone_number_verified`).
	UserAddress       string = "address"        // Access to the user's address.
	UserOfflineAccess string = "offline_access" // Access to the user's information while they are offline.
)

// SupportedScopes is a map of scopes supported by the application.
// The key is the scope, and the value indicates whether it is supported.
var SupportedScopes = map[string]bool{
	ClientRead:   true,
	ClientWrite:  true,
	ClientDelete: true,
	ClientManage: true,

	TokenIntrospect: true,
	TokenRevoke:     true,

	UserManage:        true,
	UserRead:          true,
	UserDelete:        true,
	UserWrite:         true,
	OIDC:              true,
	UserProfile:       true,
	UserEmail:         true,
	UserPhone:         true,
	UserAddress:       true,
	UserOfflineAccess: true,
}
