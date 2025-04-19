package domain

import "context"

// EmailService defines methods for sending emails, testing connections,
// and managing email retry queues.
type EmailService interface {
	// SendEmail sends an email based on the provided request.
	// It returns an error if the email could not be sent.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- request *EmailRequest: The email request containing necessary details for sending the email.
	//
	// Returns:
	//	- error: An error indicating the failure to send the email, or nil if successful.
	SendEmail(ctx context.Context, request *EmailRequest) error

	// TestConnection tests the connection to the email service.
	// It returns an error if the connection test fails.
	//
	// Returns:
	//	- error: An error indicating the failure of the connection test, or nil if successful.
	TestConnection() error

	// GetEmailRetryQueue retrieves the current email retry queue.
	// The retry queue contains emails that failed to send and are awaiting retry.
	//
	// Returns:
	//	- *EmailRetryQueue: The current retry queue. If there are no failed emails, returns an empty queue.
	GetEmailRetryQueue() *EmailRetryQueue
}
