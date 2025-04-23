package constants

// Predefined user roles
const (
	UserRole       string = "USER"
	AdminRole      string = "ADMIN"
	SuperAdminRole string = "SUPER_ADMIN"
	AuditorRole    string = "AUDITOR"
)

var ValidRoles = map[string]bool{
	UserRole:       true,
	AdminRole:      true,
	SuperAdminRole: true,
	AuditorRole:    true,
}
