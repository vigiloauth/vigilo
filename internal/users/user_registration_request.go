package users

import (
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"unicode"
)

type UserRegistrationRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (req *UserRegistrationRequest) Validate() error {
	if req.Username == "" || len(req.Username) == 0 {
		return errors.NewEmptyInputError("username")
	}
	if req.Email == "" || len(req.Email) == 0 {
		return errors.NewEmptyInputError("email")
	}
	if err := validatePassword(req.Password); err != nil {
		return err
	}
	return nil
}

func validatePassword(password string) error {
	if password == "" || len(password) == 0 {
		return errors.NewEmptyInputError("password")
	}

	if err := validatePasswordLength(password); err != nil {
		return err
	}
	if err := validatePasswordContainsUppercase(password); err != nil {
		return err
	}
	if err := validatePasswordContainsNumber(password); err != nil {
		return err
	}
	if err := validatePasswordContainsSymbol(password); err != nil {
		return err
	}

	return nil
}

func validatePasswordLength(password string) error {
	minLength := config.GetPasswordConfiguration().GetMinimumLength()
	if len(password) < minLength {
		return errors.NewPasswordLengthError(minLength)
	}
	return nil
}

func validatePasswordContainsUppercase(password string) error {
	if config.GetPasswordConfiguration().GetRequireUppercase() {
		hasUpper := false
		for _, c := range password {
			if unicode.IsUpper(c) {
				hasUpper = true
				break
			}
		}
		if !hasUpper {
			return &errors.InputValidationError{
				Field:     "password",
				ErrorCode: errors.ErrCodeMissingUppercase,
				Message:   "Password must contain at least one uppercase letter",
			}
		}
	}
	return nil
}

func validatePasswordContainsNumber(password string) error {
	if config.GetPasswordConfiguration().GetRequireNumber() {
		hasNumber := false
		for _, c := range password {
			if unicode.IsNumber(c) {
				hasNumber = true
				break
			}
		}
		if !hasNumber {
			return &errors.InputValidationError{
				Field:     "password",
				ErrorCode: errors.ErrCodeMissingNumber,
				Message:   "Password must contain at least one numeric digit",
			}
		}
	}
	return nil
}

func validatePasswordContainsSymbol(password string) error {
	if config.GetPasswordConfiguration().GetRequireSymbol() {
		hasSymbol := false
		for _, c := range password {
			if unicode.IsSymbol(c) {
				hasSymbol = true
				break
			}
		}
		if !hasSymbol {
			return &errors.InputValidationError{
				Field:     "password",
				ErrorCode: errors.ErrCodeMissingSymbol,
				Message:   "Password must contain at least one symbol",
			}
		}
	}
	return nil
}
