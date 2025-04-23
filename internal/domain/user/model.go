package domain

import (
	"slices"
	"time"
)

// User represents a user in the system.
type User struct {
	ID              string    // Unique identifier for the user.
	Username        string    // User's username.
	Email           string    // User's email address.
	Password        string    // User's password (hashed).
	Scopes          []string  // User's scopes (permissions).
	Role            string    // User's role.
	LastFailedLogin time.Time // Timestamp of the last failed login attempt.
	CreatedAt       time.Time // Timestamp of when the user was created.
	AccountLocked   bool      // Indicates if the user's account is locked.
	Verified        bool      // Indicates if the user's account has been verified.
}

// UserRegistrationRequest represents the registration request payload.
type UserRegistrationRequest struct {
	Username string   `json:"username"`         // Username for the new user.
	Email    string   `json:"email"`            // Email address for the new user.
	Password string   `json:"password"`         // Password for the new user.
	Scopes   []string `json:"scopes,omitempty"` // Scopes for the new user.
	Role     string   `json:"role,omitempty"`   // Role for the new user
}

// UserRegistrationResponse represents the registration response payload.
type UserRegistrationResponse struct {
	Username string `json:"username"` // The username of the registered user.
	Email    string `json:"email"`    // The email of the registered user.
	JWTToken string `json:"token"`    // JWT token for the registered user.
}

// UserLoginRequest represents the login request payload.
type UserLoginRequest struct {
	ID       string `json:"user_id"`  // User's ID.
	Username string `json:"username"` // User's username.
	Password string `json:"password"` // User's password.
}

// UserLoginResponse represents the login response payload.
type UserLoginResponse struct {
	UserID           string
	Username         string    `json:"username"`                     // The username of the authenticated user.
	Email            string    `json:"email"`                        // The email of the authenticated user.
	JWTToken         string    `json:"token"`                        // JWT token for the authenticated user.
	OAuthRedirectURL string    `json:"oauth_redirect_url,omitempty"` // OAuth Redirect URL for the authenticated user.
	LastFailedLogin  time.Time `json:"last_failed_login"`            // Timestamp of the last failed login attempt.
	Scopes           []string  `json:"scopes,omitempty"`
	Role             string    `json:"role,omitempty"`
}

// UserPasswordResetRequest represents the password reset request payload.
type UserPasswordResetRequest struct {
	Email       string `json:"email"`        // User's email address.
	ResetToken  string `json:"reset_token"`  // Password reset token.
	NewPassword string `json:"new_password"` // New password for the user.
}

// UserPasswordResetResponse represents the password reset response payload.
type UserPasswordResetResponse struct {
	Message string `json:"message"` // Message indicating the result of the password reset.
}

// UserLoginAttempt represents a user's login attempt.
type UserLoginAttempt struct {
	UserID          string // UserID associated with the login attempt.
	IPAddress       string // IP address from which the login attempt was made.
	Username        string
	Password        string
	ForwardedFor    string    // X-Forwarded-For header value (if present).
	Timestamp       time.Time // Timestamp of the login attempt.
	RequestMetadata string    // Additional request metadata (e.g., headers).
	Details         string    // Details about the login attempt (e.g., error messages).
	UserAgent       string    // User agent of the client making the login attempt.
	FailedAttempts  int       // Number of failed attempts (if applicable).
}

// NewUser creates a new User instance.
//
// Parameters:
//
//	username string: The user's username.
//	email string: The user's email address.
//	password string: The user's password (hashed).
//
// Returns:
//
//	*User: A new User instance.
func NewUser(username, email, password string) *User {
	return &User{
		Username:        username,
		Email:           email,
		Password:        password,
		LastFailedLogin: time.Time{},
		AccountLocked:   false,
		Verified:        false,
	}
}

// NewUserRegistrationRequest creates a new UserRegistrationRequest instance.
//
// Parameters:
//
//	username string: The username for the registration request.
//	email string: The email for the registration request.
//	password string: The password for the registration request.
//
// Returns:
//
//	*UserRegistrationRequest: A new UserRegistrationRequest instance.
func NewUserRegistrationRequest(username, email, password string) *UserRegistrationRequest {
	return &UserRegistrationRequest{
		Username: username,
		Email:    email,
		Password: password,
	}
}

// NewUserRegistrationResponse creates a new UserRegistrationResponse instance.
//
// Parameters:
//
//	user *User: The created User object.
//	jwtToken string: The JWT token for the registered user.
//
// Returns:
//
//	*UserRegistrationResponse: A new UserRegistrationResponse instance.
func NewUserRegistrationResponse(user *User, jwtToken string) *UserRegistrationResponse {
	return &UserRegistrationResponse{
		Username: user.Username,
		Email:    user.Email,
		JWTToken: jwtToken,
	}
}

// NewUserLoginRequest creates a new UserLoginRequest instance.
//
// Parameters:
//
//	id string: The user's id.
//	username string: The username for the login request.
//	password string: The password for the login request.
//
// Returns:
//
//	*UserLoginRequest: A new UserLoginRequest instance.
func NewUserLoginRequest(id, username, password string) *UserLoginRequest {
	return &UserLoginRequest{
		ID:       id,
		Username: username,
		Password: password,
	}
}

// NewUserLoginResponse creates a new UserLoginResponse instance.
//
// Parameters:
//
//	user *User: The authenticated User object.
//	jwtToken string: The JWT token for the authenticated user.
//
// Returns:
//
//	*UserLoginResponse: A new UserLoginResponse instance.
func NewUserLoginResponse(user *User, jwtToken string) *UserLoginResponse {
	return &UserLoginResponse{
		UserID:          user.ID,
		Username:        user.Username,
		Email:           user.Email,
		Scopes:          user.Scopes,
		Role:            user.Role,
		JWTToken:        jwtToken,
		LastFailedLogin: user.LastFailedLogin,
	}
}

// NewUserLoginAttempt creates a new UserLoginAttempt instance.
//
// Parameters:
//
//	ipAddress string: The IP address of the login attempt.
//	requestMetadata string: Additional request metadata.
//	details string: Details about the login attempt.
//	userAgent string: The user agent of the login attempt.
//
// Returns:
//
//	*LoginAttempt: A new UserLoginAttempt instance.
func NewUserLoginAttempt(ipAddress, userAgent string) *UserLoginAttempt {
	return &UserLoginAttempt{
		IPAddress:      ipAddress,
		Timestamp:      time.Now(),
		UserAgent:      userAgent,
		FailedAttempts: 0,
	}
}

func (u *User) HasScope(scope string) bool {
	return slices.Contains(u.Scopes, scope)
}

func (u *User) HasRole(role string) bool {
	return u.Role == role
}
