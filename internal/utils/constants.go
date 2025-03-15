package utils

var UserFieldConstants = struct {
	Username string
	Email    string
	Password string
}{
	Username: "username",
	Email:    "email",
	Password: "password",
}

const defaultAuthEndpoint string = "/auth"

var UserEndpoints = struct {
	Registration         string
	Login                string
	Logout               string
	RequestPasswordReset string
	ResetPassword        string
}{
	Registration:         defaultAuthEndpoint + "/signup",
	Login:                defaultAuthEndpoint + "/login",
	Logout:               defaultAuthEndpoint + "/logout",
	RequestPasswordReset: defaultAuthEndpoint + "/reset-password",
	ResetPassword:        defaultAuthEndpoint + "/reset-password/confirm",
}

const (
	TestEmail           string = "test@email.com"
	TestUsername        string = "username"
	TestPassword1       string = "Pa$s_W0Rd_"
	TestPassword2       string = "__Pa$$_w0rD"
	InvalidPassword     string = "invalid"
	TestIPAddress       string = "127.001.00"
	TestRequestMetadata string = "request_metadata"
	TestRequestDetails  string = "details"
	TestUserAgent       string = "user_agent"
)
