package users

import "fmt"

type EmailFormatError struct {
	Email string
}

func (e *EmailFormatError) Error() string {
	return fmt.Sprintf("Email format error: %s", e.Email)
}

type PasswordLengthError struct {
	Length int
}

func (e *PasswordLengthError) Error() string {
	return fmt.Sprintf("Password length error: %d", e.Length)
}

type DuplicateUserError struct {
	Message string
}

func (e *DuplicateUserError) Error() string {
	return fmt.Sprintf("Duplicate user: %s", e.Message)
}

type EmptyInputError struct {
	Message string
}

func (e *EmptyInputError) Error() string {
	return fmt.Sprintf("Empty input: %s", e.Message)
}
