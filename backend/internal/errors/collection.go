package errors

import "fmt"

type ErrorCollection struct {
	errors []error
}

// NewErrorCollection creates a new collection of errors
func NewErrorCollection() *ErrorCollection {
	return &ErrorCollection{
		errors: []error{},
	}
}

// Add adds an error to the collection
func (ec *ErrorCollection) Add(err error) {
	ec.errors = append(ec.errors, err)
}

// Errors returns the list of validation errors
func (ec *ErrorCollection) Errors() *[]error {
	return &ec.errors
}

// HasErrors checks if there are any validation errors
func (ec *ErrorCollection) HasErrors() bool {
	return len(ec.errors) > 0
}

// Error implements the error interface
func (ec *ErrorCollection) Error() string {
	return fmt.Sprintf("%d errors", len(ec.errors))
}
