package constants

const (
	// Client Management Scopes
	ClientRead   string = "clients:read"   // Read registered client details.
	ClientWrite  string = "clients:write"  // Modify client details (except 'client_id' & 'client_secret')
	ClientDelete string = "clients:delete" // Delete a registered client.
	ClientManage string = "clients:manage" // Full control over all clients (includes 'read', 'write', and 'delete')

	// Token Management Scopes
	TokenIntrospect string = "tokens:introspect"
	TokenRevoke     string = "tokens:revoke"

	// User Management Scopes
	UserRead          string = "users:read"           // Read user details (e.g., profile, email, etc.).
	UserWrite         string = "users:write"          // Modify user details.
	UserDelete        string = "users:delete"         // Delete a user account.
	UserManage        string = "users:manage"         // Full control over users ('read', 'write'. and 'delete').
	UserProfile       string = "users:profile"        // Access to user profile (`name`, `middle_name`, `family_name`, `birthdate`, and `update_at`).
	UserEmail         string = "users:email"          // Access to the user's email address (`email` and `email_verified`).
	UserPhone         string = "users:phone"          // Access to the user's phone number (`phone_number` and `phone_number_verified`).
	UserAddress       string = "users:address"        // Access to the user's address.
	UserOfflineAccess string = "users:offline_access" // Access to the user's information while they are offline.
)

var ValidScopes = map[string]bool{
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
	UserProfile:       true,
	UserEmail:         true,
	UserPhone:         true,
	UserAddress:       true,
	UserOfflineAccess: true,
}
