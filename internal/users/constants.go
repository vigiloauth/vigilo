package users

var TestConstants = struct {
	Username        string
	Email           string
	Password        string
	DuplicateEmail  string
	InvalidPassword string
	IPAddress       string
	RequestMetadata string
	Details         string
	UserAgent       string
}{
	Username:        "username",
	Email:           "vigilo@vigiloauth.com",
	Password:        "Pa$s_w0rds",
	DuplicateEmail:  "duplicate_email@test.com",
	InvalidPassword: "invalid",
	IPAddress:       "127.001.00",
	RequestMetadata: "request_metadata",
	Details:         "details",
	UserAgent:       "user_agent",
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
	Login        string
}{
	Registration: "/users",
	Login:        "/login",
}
