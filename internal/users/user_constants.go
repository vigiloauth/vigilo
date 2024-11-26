package users

var TestConstants = struct {
	Username        string
	Email           string
	Password        string
	DuplicateEmail  string
	InvalidPassword string
}{
	Username:        "username",
	Email:           "email@test.com",
	Password:        "Pa$s_w0rds",
	DuplicateEmail:  "duplicate_email@test.com",
	InvalidPassword: "invalid",
}

var UserFieldConstants = struct {
	Username string
	Email    string
	Password string
}{
	Username: "username",
	Email:    "email",
	Password: "password",
}

var UserEndpoints = struct {
	Registration string
}{
	Registration: "/vigilo/identity/users",
}
