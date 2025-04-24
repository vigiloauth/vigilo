package constants

// Predefined user roles
const (
	UserRole  string = "USER"
	AdminRole string = "ADMIN"
)

var ValidRoles = map[string]bool{
	UserRole:  true,
	AdminRole: true,
}
