package email

import "time"

// EmailService defines the interface for sending emails.
type EmailService interface {
	// SendEmail sends an email based on the provided EmailRequest.
	//
	// Parameters:
	//   request EmailRequest: The email request to send.
	//
	// Returns:
	//   error: An error if sending the email fails.
	SendEmail(request EmailRequest) error

	// GenerateEmail populates an EmailRequest with necessary data based on the request type.
	//
	// Parameters:
	//   request EmailRequest: The email request to generate.
	//
	// Returns:
	//   *EmailRequest: The generated email request.
	GenerateEmail(request EmailRequest) *EmailRequest

	// SetTemplate sets the email template to be used for sending emails.
	//
	// Parameters:
	//   template string: The path to the email template.
	//
	// Returns:
	//   error: An error if setting the template fails.
	SetTemplate(template string) error

	// TestConnection tests the connection to the SMTP server.
	//
	// Returns:
	//   error: An error if the connection test fails.
	TestConnection() error

	// ProcessQueue processes the email queue, sending emails in the queue.
	ProcessQueue()

	// StartQueueProcessor starts a background process to periodically process the email queue.
	//
	// Parameters:
	//   interval time.Duration: The interval between queue processing.
	StartQueueProcessor(interval time.Duration)

	// GetQueueStatus returns the current status of the email queue, including queue length and retry counts.
	//
	// Returns:
	//   int: The current length of the email queue.
	//   map[string]int: A map of application IDs to retry counts.
	GetQueueStatus() (int, map[string]int)

	// ClearQueue clears the email queue.
	ClearQueue()
}

const (
	TestSMTPServer        string = "localhost"              // Test SMTP server address.
	TestSMTPPort          int    = 2525                     // Test SMTP server port.
	TestInvalidSMTPServer string = "invalid-smt-server.com" // Invalid test SMTP server address.
	TestFromAddress       string = "no-reply@example.com"   // Test sender email address.
	TestRecipient         string = "user@example.com"       // Test recipient email address.
	TestApplicationID     string = "TestApp"                // Test application ID.
)
