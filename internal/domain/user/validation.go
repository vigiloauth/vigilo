package domain

import (
	"fmt"
	"net/mail"
	"strings"
	"unicode"

	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/constants"
	"github.com/vigiloauth/vigilo/internal/errors"
)

// Validate validates the UserRegistrationRequest fields.
//
// Returns:
//
//	error: An ErrorCollection if validation fails, or nil if validation succeeds.
func (req *UserRegistrationRequest) Validate() error {
	errorCollection := errors.NewErrorCollection()

	if req.Username == "" {
		err := errors.New(errors.ErrCodeEmptyInput, "'username' is empty")
		errorCollection.Add(err)
	}

	if len(req.Scopes) > 0 {
		for _, scope := range req.Scopes {
			if _, ok := constants.ValidScopes[scope]; !ok {
				err := errors.New(errors.ErrCodeBadRequest, fmt.Sprintf("invalid scope '%s'", scope))
				errorCollection.Add(err)
			}
		}
	}

	validateEmail(req.Email, errorCollection)
	validatePassword(req.Password, errorCollection)
	req.validateRole(errorCollection)

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

	if req.Password == "" {
		err := errors.New(errors.ErrCodeEmptyInput, "'password' is empty")
		errorCollection.Add(err)
	}
	if req.Username == "" {
		err := errors.New(errors.ErrCodeEmptyInput, "'username' is empty")
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
		err := errors.New(errors.ErrCodeEmptyInput, "'email' is empty")
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
		err := errors.New(errors.ErrCodeMissingSymbol, "password is missing a required symbol")
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

func (req *UserRegistrationRequest) validateRole(errorCollection *errors.ErrorCollection) {
	if req.Role == "" {
		req.Role = constants.UserRole
		return
	}

	if _, ok := constants.ValidRoles[req.Role]; !ok {
		errorCollection.Add(errors.New(errors.ErrCodeBadRequest, fmt.Sprintf("invalid role: %s", req.Role)))
	}
}
