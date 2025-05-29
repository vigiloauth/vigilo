package constants

// Predefined user roles define the roles that can be assigned to users
// in the application. These roles determine the level of access and permissions.
const (
	UserRole  string = "USER"  // Standard user role with limited access
	AdminRole string = "ADMIN" // Administrator role with elevated privileges
)

// ValidRoles is a map of roles supported by the application.
// The key is the role, and the value indicates whether it is valid.
var ValidRoles = map[string]bool{
	UserRole:  true,
	AdminRole: true,
}
