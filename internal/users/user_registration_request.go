package users

import (
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"regexp"
	"unicode"
)

type UserRegistrationRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func NewUserRegistrationRequest(username, email, password string) *UserRegistrationRequest {
	return &UserRegistrationRequest{
		Username: username,
		Email:    email,
		Password: password,
	}
}

func (req *UserRegistrationRequest) Validate() error {
	errorCollection := errors.NewErrorCollection()

	if req.Username == "" {
		errorCollection.Add(errors.NewEmptyInputError(UserFieldConstants.Username))
	}

	if req.Email == "" {
		errorCollection.Add(errors.NewEmptyInputError(UserFieldConstants.Email))
	} else if !isValidEmailFormat(req.Email) {
		errorCollection.Add(errors.NewEmailFormatError(req.Email))
	}

	validatePassword(req.Password, errorCollection)
	if errorCollection.HasErrors() {
		return errorCollection
	}

	return nil
}

func validatePassword(password string, errorCollection *errors.ErrorCollection) {
	if password == "" {
		errorCollection.Add(errors.NewEmptyInputError(UserFieldConstants.Password))
		return
	}

	passwordConfig := config.GetPasswordConfiguration()
	minimumLength := passwordConfig.GetMinimumLength()

	if len(password) < minimumLength {
		errorCollection.Add(errors.NewPasswordLengthError(minimumLength))
	}

	if passwordConfig.GetRequireUppercase() && !containsUppercase(password) {
		errorCollection.Add(&errors.InputValidationError{
			Field:     UserFieldConstants.Password,
			ErrorCode: errors.ErrCodeMissingUppercase,
			Message:   "Password must contain at least one uppercase letter",
		})
	}

	if passwordConfig.GetRequireNumber() && !containsNumber(password) {
		errorCollection.Add(&errors.InputValidationError{
			Field:     UserFieldConstants.Password,
			ErrorCode: errors.ErrCodeMissingNumber,
			Message:   "Password must contain at least one numeric digit",
		})
	}

	if passwordConfig.GetRequireSymbol() && !containsSymbol(password) {
		errorCollection.Add(&errors.InputValidationError{
			Field:     UserFieldConstants.Password,
			ErrorCode: errors.ErrCodeMissingSymbol,
			Message:   "Password must contain at least one symbol",
		})
	}
}

func containsUppercase(password string) bool {
	for _, c := range password {
		if unicode.IsUpper(c) {
			return true
		}
	}
	return false
}

func containsNumber(password string) bool {
	for _, c := range password {
		if unicode.IsNumber(c) {
			return true
		}
	}
	return false
}

func containsSymbol(password string) bool {
	for _, c := range password {
		if unicode.IsSymbol(c) {
			return true
		}
	}
	return false
}

func isValidEmailFormat(email string) bool {
	pattern := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	return pattern.MatchString(email)
}
