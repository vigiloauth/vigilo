package users

import (
	"net/mail"
	"unicode"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/security"
)

// UserRegistration handles user registration operations.
type UserRegistration struct {
	userStore UserStore
}

// NewUserRegistration creates a new UserRegistration instance.
func NewUserRegistration(userStore UserStore) *UserRegistration {
	return &UserRegistration{userStore: userStore}
}

// RegisterUser registers a new user in the system.
// It takes a User object as input, hashes the user's password, and stores the user in the userStore.
// Returns the registered User object and an error if any occurred during the process.
func (r *UserRegistration) RegisterUser(user *User) (*User, error) {
	hashedPassword, err := security.HashPassword(user.Password)
	if err != nil {
		return nil, err
	}
	user.Password = hashedPassword
	if err := r.userStore.AddUser(user); err != nil {
		return nil, err
	}

	return user, nil
}

// Validate ensures the registration request contains valid data and formatting.
func (req *UserRegistrationRequest) Validate() error {
	errorCollection := errors.NewErrorCollection()

	if req.Username == "" {
		errorCollection.Add(errors.NewEmptyInputError(UserFieldConstants.Username))
	}

	if req.Email == "" {
		errorCollection.Add(errors.NewEmptyInputError(UserFieldConstants.Email))
	} else if !isValidEmailFormat(req.Email) {
		errorCollection.Add(errors.NewEmailFormatError(UserFieldConstants.Email))
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
		errorCollection.Add(errors.NewPasswordFormatError("uppercase letter", errors.ErrCodeMissingUppercase))
	}

	if passwordConfig.GetRequireNumber() && !containsNumber(password) {
		errorCollection.Add(errors.NewPasswordFormatError("number", errors.ErrCodeMissingNumber))
	}

	if passwordConfig.GetRequireSymbol() && !containsSymbol(password) {
		errorCollection.Add(errors.NewPasswordFormatError("symbol", errors.ErrCodeMissingSymbol))
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
		if !(unicode.IsLetter(c) || unicode.IsNumber(c)) {
			return true
		}
	}
	return false
}

func isValidEmailFormat(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
