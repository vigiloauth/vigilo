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
}

// UserLoginRequest represents the login request payload
type UserLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// UserLoginResponse represents the login response payload
type UserLoginResponse struct {
	Token string `json:"token"`
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

// NewUserLoginResponse creates a new login response returning a token
func NewUserLoginResponse() *UserLoginResponse {
	return &UserLoginResponse{}
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) SetEmail(email string) {
	u.Email = email
}

func (u *User) GetID() string {
	return u.ID
}

func (u *User) SetID(id string) {
	u.ID = id
}

func (u *User) GetPassword() string {
	return u.Password
}

func (u *User) SetPassword(password string) {
	u.Password = password
}

func (u *User) GetUsername() string {
	return u.Username
}

func (u *User) SetUsername(username string) {
	u.Username = username
}
