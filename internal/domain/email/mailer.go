package domain

import "gopkg.in/gomail.v2"

// Mailer defines methods for interacting with an email service using gomail.
// It includes functionality for dialing, sending emails, and creating email messages.
type Mailer interface {
	// Dial establishes a connection to the email server with the provided host, port,
	// username, and password. It returns a `gomail.SendCloser` which can be used
	// to send emails, or an error if the connection fails.
	//
	// Parameters:
	//	- host string: The email server's host.
	//	- port string: The port number to connect to on the email server.
	//	- username string: The username for authenticating to the email server.
	//	- password string: The password for authenticating to the email server.
	//
	// Returns:
	//	- gomail.SendCloser: A send closer to send emails.
	//	- error: An error if the connection fails, or nil if successful.
	Dial(host string, port int, username string, password string) (gomail.SendCloser, error)

	// DialAndSend connects to the email server and immediately sends the provided email message(s).
	// It returns an error if the connection or sending process fails.
	//
	// Parameters:
	//	- host string: The email server's host.
	//	- port string: The port number to connect to on the email server.
	//	- username string: The username for authenticating to the email server.
	//	- password string: The password for authenticating to the email server.
	//	- message string: A list of gomail messages to send. One or more messages can be provided.
	//
	// Returns:
	//	- error: An error indicating the failure to send the email(s), or nil if successful.
	DialAndSend(host string, port int, username string, password string, message ...*gomail.Message) error

	// NewMessage creates a new gomail message using the provided email request, body,
	// subject, and sender address. This message can then be sent using the DialAndSend method.
	//
	// Parameters:
	//	- request string: The request object containing email details.
	//	- body string: The body content of the email.
	//	- subject string: The subject of the email.
	//	- fromAddress string: The sender's email address.
	//
	// Returns:
	//	- *gomail.Message: A new gomail message containing the provided email details.
	NewMessage(request *EmailRequest, body string, subject string, fromAddress string) *gomail.Message
}
