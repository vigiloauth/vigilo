package utils

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

var ClientEndpoints = struct {
	Registration string
}{
	Registration: "/clients",
}
