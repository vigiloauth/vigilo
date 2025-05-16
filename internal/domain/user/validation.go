package domain

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
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

	validateEmail(req.Email, errorCollection)
	validatePassword(req.Password, errorCollection)
	validatePhoneNumber(req.PhoneNumber, errorCollection)
	validateBirthdate(req.Birthdate, errorCollection)
	req.validateRole(errorCollection)

	if errorCollection.HasErrors() {
		return errorCollection
	}

	return nil
}

// Validate validates the UserPasswordResetRequest fields.
//
// Returns:
//   - error: An ErrorCollection if validation fails, or nil if validation succeeds.
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
//   - error: An ErrorCollection if validation fails, or nil if validation succeeds.
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
//   - email string: The email address to validate.
//   - errorCollection *errors.ErrorCollection: The ErrorCollection to add errors to.
func validateEmail(email string, errorCollection *errors.ErrorCollection) {
	if email == "" {
		err := errors.New(errors.ErrCodeEmptyInput, "'email' is empty")
		errorCollection.Add(err)
	} else if !isValidEmailFormat(email) {
		err := errors.New(errors.ErrCodeInvalidFormat, "invalid email format")
		errorCollection.Add(err)
	}
}

// validatePassword validates the password and adds errors to the ErrorCollection.
//
// Parameters:
//   - password string: The password to validate.
//   - errorCollection *errors.ErrorCollection: The ErrorCollection to add errors to.
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

// validateBirthdate validates the user's password and ensures it follows the
// ISO 8601:2004 YYYY-MM-DD format
//
// Parameters:
//   - birthdate: The birthdate to validate.
//   - errorCollection *errors.ErrorCollection: The ErrorCollection to add errors to.
func validateBirthdate(birthdate string, errorCollection *errors.ErrorCollection) {
	if birthdate == "" {
		err := errors.New(errors.ErrCodeEmptyInput, "birthdate is empty")
		errorCollection.Add(err)
		return
	}

	const pattern string = `^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$`
	re := regexp.MustCompile(pattern)

	if !re.MatchString(birthdate) {
		err := errors.New(errors.ErrCodeInvalidFormat, "invalid birthdate format - must follow the ISO 8601:2004 YYYY-MM-DD format")
		errorCollection.Add(err)
		return
	}

	const dateFormat string = "2006-01-02"
	if _, err := time.Parse(dateFormat, birthdate); err != nil {
		err := errors.New(errors.ErrCodeInvalidDate, "the birthdate provided is an invalid date")
		errorCollection.Add(err)
		return
	}
}

// validatePhoneNumber validates the phone number and makes sure it is in E.164 format.
//
// Parameters:
//   - phoneNumber string: The phone number to verify.
//   - errorCollection *errors.ErrorCollection: The ErrorCollection to add errors to.
func validatePhoneNumber(phoneNumber string, errorCollection *errors.ErrorCollection) {
	if phoneNumber == "" {
		return
	}

	const e164Format string = `^\+[1-9]\d{1,14}$`
	re := regexp.MustCompile(e164Format)
	if !re.MatchString(phoneNumber) {
		err := errors.New(errors.ErrCodeInvalidFormat, "invalid phone number format")
		errorCollection.Add(err)
		return
	}
}

// isValidEmailFormat validates the email format.
//
// Parameters:
//   - email string: The email address to validate.
//
// Returns:
//   - bool: True if the email format is valid, false otherwise.
func isValidEmailFormat(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
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
	if len(req.Roles) == 0 {
		req.Roles = append(req.Roles, constants.UserRole)
	}

	for _, role := range req.Roles {
		if _, ok := constants.ValidRoles[role]; !ok {
			errorCollection.Add(errors.New(errors.ErrCodeBadRequest, fmt.Sprintf("invalid role: %s", role)))
		}
	}
}
