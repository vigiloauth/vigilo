package users

import (
	"net/mail"
	"strings"
	"time"
	"unicode"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
)

// User represents a user in the system.
type User struct {
	ID              string    // Unique identifier for the user.
	Username        string    // User's username.
	Email           string    // User's email address.
	Password        string    // User's password (hashed).
	LastFailedLogin time.Time // Timestamp of the last failed login attempt.
	AccountLocked   bool      // Indicates if the user's account is locked.
}

// UserRegistrationRequest represents the registration request payload.
type UserRegistrationRequest struct {
	Username string `json:"username"` // Username for the new user.
	Email    string `json:"email"`    // Email address for the new user.
	Password string `json:"password"` // Password for the new user.
}

// UserRegistrationResponse represents the registration response payload.
type UserRegistrationResponse struct {
	Username string `json:"username"` // The username of the registered user.
	Email    string `json:"email"`    // The email of the registered user.
	JWTToken string `json:"token"`    // JWT token for the registered user.
}

// UserLoginRequest represents the login request payload.
type UserLoginRequest struct {
	Email    string `json:"email"`    // User's email address.
	Password string `json:"password"` // User's password.
}

// UserLoginResponse represents the login response payload.
type UserLoginResponse struct {
	Username        string    `json:"username"`          // The username of the registered user.
	Email           string    `json:"email"`             // The email of the registered user.
	JWTToken        string    `json:"token"`             // JWT token for the registered user.
	LastFailedLogin time.Time `json:"last_failed_login"` // Timestamp of the last failed login attempt.
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
//	email string: The email for the login request.
//	password string: The password for the login request.
//
// Returns:
//
//	*UserLoginRequest: A new UserLoginRequest instance.
func NewUserLoginRequest(email, password string) *UserLoginRequest {
	return &UserLoginRequest{
		Email:    email,
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
		Username:        user.Username,
		Email:           user.Email,
		JWTToken:        jwtToken,
		LastFailedLogin: user.LastFailedLogin,
	}
}

// Validate validates the UserRegistrationRequest fields.
//
// Returns:
//
//	error: An ErrorCollection if validation fails, or nil if validation succeeds.
func (req *UserRegistrationRequest) Validate() error {
	errorCollection := errors.NewErrorCollection()

	if req.Username == "" {
		err := errors.New(errors.ErrCodeEmptyInput, "username is empty")
		errorCollection.Add(err)
	}

	validateEmail(req.Email, errorCollection)
	validatePassword(req.Password, errorCollection)

	if errorCollection.HasErrors() {
		return errorCollection
	}

	return nil
}

// Validate validates the UserPasswordResetRequest fields.
//
// Returns:
//
//	error: An ErrorCollection if validation fails, or nil if validation succeeds.
func (req *UserPasswordResetRequest) Validate() error {
	errorCollection := errors.NewErrorCollection()
	validatePassword(req.NewPassword, errorCollection)

	if errorCollection.HasErrors() {
		return errorCollection
	}

	return nil
}

// Validate validates the UserLoginRequest fields.
//
// Returns:
//
//	error: An ErrorCollection if validation fails, or nil if validation succeeds.
func (req *UserLoginRequest) Validate() error {
	errorCollection := errors.NewErrorCollection()
	validateEmail(req.Email, errorCollection)

	if req.Password == "" {
		err := errors.New(errors.ErrCodeEmptyInput, "password is empty")
		errorCollection.Add(err)
	}

	if errorCollection.HasErrors() {
		return errorCollection
	}

	return nil
}

// validateEmail validates the email format and adds errors to the ErrorCollection.
//
// Parameters:
//
//	email string: The email address to validate.
//	errorCollection *errors.ErrorCollection: The ErrorCollection to add errors to.
func validateEmail(email string, errorCollection *errors.ErrorCollection) {
	if email == "" {
		err := errors.New(errors.ErrCodeEmptyInput, "email is empty")
		errorCollection.Add(err)
	} else if !isValidEmailFormat(email) {
		err := errors.New(errors.ErrCodeInvalidFormat, "invalid email format")
		errorCollection.Add(err)
	}
}

// isValidEmailFormat validates the email format.
//
// Parameters:
//
//	email string: The email address to validate.
//
// Returns:
//
//	bool: True if the email format is valid, false otherwise.
func isValidEmailFormat(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// validatePassword validates the password and adds errors to the ErrorCollection.
//
// Parameters:
//
//	password string: The password to validate.
//	errorCollection *errors.ErrorCollection: The ErrorCollection to add errors to.
func validatePassword(password string, errorCollection *errors.ErrorCollection) {
	if password == "" {
		err := errors.New(errors.ErrCodeEmptyInput, "password is empty")
		errorCollection.Add(err)
		return
	}

	passwordConfig := config.GetServerConfig().PasswordConfig()
	minimumLength := passwordConfig.MinLength()

	if len(password) < minimumLength {
		err := errors.New(errors.ErrCodePasswordLength, "password does not match required length")
		errorCollection.Add(err)
	}

	if passwordConfig.RequireUppercase() && !containsUppercase(password) {
		err := errors.New(errors.ErrCodeMissingUppercase, "password is missing a required uppercase letter")
		errorCollection.Add(err)
	}

	if passwordConfig.RequireNumber() && !containsNumber(password) {
		err := errors.New(errors.ErrCodeMissingNumber, "password is missing a required number")
		errorCollection.Add(err)
	}

	if passwordConfig.RequireSymbol() && !containsSymbol(password) {
		err := errors.New(errors.ErrCodeMissingSymbol, "password is missing a required symbold")
		errorCollection.Add(err)
	}
}

func containsUppercase(password string) bool {
	return strings.IndexFunc(password, unicode.IsUpper) >= 0
}

func containsNumber(password string) bool {
	return strings.IndexFunc(password, unicode.IsNumber) >= 0
}

func containsSymbol(password string) bool {
	return strings.IndexFunc(password, func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsNumber(r))
	}) >= 0
}
