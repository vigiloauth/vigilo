package constants

// Predefined user roles
const (
	RoleUser       string = "USER"
	RoleAdmin      string = "ADMIN"
	RoleSuperAdmin string = "SUPER_ADMIN"
	RoleAuditor    string = "AUDITOR"
)

var ValidRoles = map[string]bool{
	RoleUser:       true,
	RoleAdmin:      true,
	RoleSuperAdmin: true,
	RoleAuditor:    true,
}
