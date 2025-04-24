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
	UserRead   string = "users:read"   // Read user details (e.g., profile, email, etc.).
	UserWrite  string = "users:write"  // Modify user details.
	UserDelete string = "users:delete" // Delete a user account.
	UserManage string = "users:manage" // Full control over users ('read', 'write'. and 'delete').
)

var ValidScopes = map[string]bool{
	ClientRead:   true,
	ClientWrite:  true,
	ClientDelete: true,
	ClientManage: true,

	TokenIntrospect: true,
	TokenRevoke:     true,

	UserManage: true,
	UserRead:   true,
	UserDelete: true,
	UserWrite:  true,
}
