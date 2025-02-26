package users

// User represents a user in the system
type User struct {
	ID       string
	Username string
	Email    string
	Password string
}

// UserRegistrationRequest represents the registration request payload
type UserRegistrationRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// UserRegistrationResponse represents the registration response payload
type UserRegistrationResponse struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	JWTToken string `json:"jwt_token"`
}

// UserLoginRequest represents the login request payload
type UserLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// UserLoginResponse represents the login response payload
type UserLoginResponse struct {
	Email    string `json:"email"`
	JWTToken string `json:"jwt_token"`
}

// NewUser creates a new user
func NewUser(username, email, password string) *User {
	return &User{
		Username: username,
		Email:    email,
		Password: password,
	}
}

// NewUserRegistrationRequest creates a new registration request
func NewUserRegistrationRequest(username, email, password string) *UserRegistrationRequest {
	return &UserRegistrationRequest{
		Username: username,
		Email:    email,
		Password: password,
	}
}

// NewUserRegistrationResponse creates a new registration response
func NewUserRegistrationResponse(username, email string) *UserRegistrationResponse {
	return &UserRegistrationResponse{
		Username: username,
		Email:    email,
	}
}

// NewUserLoginRequest creates a new login request
func NewUserLoginRequest(email, password string) *UserLoginRequest {
	return &UserLoginRequest{
		Email:    email,
		Password: password,
	}
}

// NewUserLoginResponse creates a new login response
func NewUserLoginResponse(email, jwtToken string) *UserLoginResponse {
	return &UserLoginResponse{
		Email:    email,
		JWTToken: jwtToken,
	}
}
