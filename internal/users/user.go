package users

import (
	"net/mail"
	"strings"
	"time"
	"unicode"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/utils"
)

// User represents a user in the system
type User struct {
	ID              string    `json:"id"`
	Username        string    `json:"username"`
	Email           string    `json:"email"`
	Password        string    `json:"password"`
	LastFailedLogin time.Time `json:"last_failed_login"`
	AccountLocked   bool      `json:"account_locked"`
}

// UserRegistrationRequest represents the registration request payload
type UserRegistrationRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// UserRegistrationResponse represents the registration response payload
type UserRegistrationResponse struct {
	User     *User
	JWTToken string `json:"token"`
}

// UserLoginRequest represents the login request payload
type UserLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// UserLoginResponse represents the login response payload
type UserLoginResponse struct {
	User     *User
	JWTToken string `json:"token"`
}

// NewUser creates a new user
func NewUser(username, email, password string) *User {
	return &User{
		Username:        username,
		Email:           email,
		Password:        password,
		LastFailedLogin: time.Time{},
		AccountLocked:   false,
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
func NewUserRegistrationResponse(user *User, jwtToken string) *UserRegistrationResponse {
	return &UserRegistrationResponse{
		User:     user,
		JWTToken: jwtToken,
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
func NewUserLoginResponse(user *User, jwtToken string) *UserLoginResponse {
	return &UserLoginResponse{
		User:     user,
		JWTToken: jwtToken,
	}
}

// Validate validates the UserRegistrationRequest fields
func (req *UserRegistrationRequest) Validate() error {
	errorCollection := errors.NewErrorCollection()

	if req.Username == "" {
		errorCollection.Add(errors.NewEmptyInputError(utils.UserFieldConstants.Username))
	}

	validateEmail(req.Email, errorCollection)
	validatePassword(req.Password, errorCollection)

	if errorCollection.HasErrors() {
		return errorCollection
	}

	return nil
}

// Validate validates the UserLoginRequest fields
func (req *UserLoginRequest) Validate() error {
	errorCollection := errors.NewErrorCollection()

	validateEmail(req.Email, errorCollection)

	if req.Password == "" {
		errorCollection.Add(errors.NewEmptyInputError(utils.UserFieldConstants.Password))
	}

	if errorCollection.HasErrors() {
		return errorCollection
	}

	return nil
}

// validateEmail validates the email format and adds errors to the ErrorCollection.
func validateEmail(email string, errorCollection *errors.ErrorCollection) {
	if email == "" {
		errorCollection.Add(errors.NewEmptyInputError(utils.UserFieldConstants.Email))
	} else if !isValidEmailFormat(email) {
		errorCollection.Add(errors.NewEmailFormatError(utils.UserFieldConstants.Email))
	}
}

// isValidEmailFormat validates the email format.
func isValidEmailFormat(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// validatePassword validates the password and adds errors to the ErrorCollection.
func validatePassword(password string, errorCollection *errors.ErrorCollection) {
	if password == "" {
		errorCollection.Add(errors.NewEmptyInputError(utils.UserFieldConstants.Password))
		return
	}

	passwordConfig := config.GetPasswordConfiguration()
	minimumLength := passwordConfig.MinLength()

	if len(password) < minimumLength {
		errorCollection.Add(errors.NewPasswordLengthError(minimumLength))
	}

	if passwordConfig.RequireUppercase() && !containsUppercase(password) {
		errorCollection.Add(errors.NewPasswordFormatError("uppercase letter", errors.ErrCodeMissingUppercase))
	}

	if passwordConfig.RequireNumber() && !containsNumber(password) {
		errorCollection.Add(errors.NewPasswordFormatError("number", errors.ErrCodeMissingNumber))
	}

	if passwordConfig.RequireSymbol() && !containsSymbol(password) {
		errorCollection.Add(errors.NewPasswordFormatError("symbol", errors.ErrCodeMissingSymbol))
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
