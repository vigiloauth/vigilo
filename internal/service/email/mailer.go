package service

import (
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/email"
	"gopkg.in/gomail.v2"
)

var _ domain.Mailer = (*goMailer)(nil)

type goMailer struct{}

func NewGoMailer() domain.Mailer {
	return &goMailer{}
}

// Dial establishes a connection to the email server with the provided host, port,
// username, and password. It returns a `gomail.SendCloser` which can be used
// to send emails, or an error if the connection fails.
//
// Parameters:
//   - host string: The email server's host.
//   - port string: The port number to connect to on the email server.
//   - username string: The username for authenticating to the email server.
//   - password string: The password for authenticating to the email server.
//
// Returns:
//   - gomail.SendCloser: A send closer to send emails.
//   - error: An error if the connection fails, or nil if successful.
func (m *goMailer) Dial(host string, port int, username string, password string) (gomail.SendCloser, error) {
	dialer := gomail.NewDialer(host, port, username, password)
	return dialer.Dial()
}

// DialAndSend connects to the email server and immediately sends the provided email message(s).
// It returns an error if the connection or sending process fails.
//
// Parameters:
//   - host string: The email server's host.
//   - port string: The port number to connect to on the email server.
//   - username string: The username for authenticating to the email server.
//   - password string: The password for authenticating to the email server.
//   - message string: A list of gomail messages to send. One or more messages can be provided.
//
// Returns:
//   - error: An error indicating the failure to send the email(s), or nil if successful.
func (m *goMailer) DialAndSend(host string, port int, username string, password string, message ...*gomail.Message) error {
	dialer := gomail.NewDialer(host, port, username, password)
	return dialer.DialAndSend(message...)
}

// NewMessage creates a new gomail message using the provided email request, body,
// subject, and sender address. This message can then be sent using the DialAndSend method.
//
// Parameters:
//   - request string: The request object containing email details.
//   - body string: The body content of the email.
//   - subject string: The subject of the email.
//   - fromAddress string: The sender's email address.
//
// Returns:
//   - *gomail.Message: A new gomail message containing the provided email details.
func (m *goMailer) NewMessage(request *domain.EmailRequest, body string, subject string, fromAddress string) *gomail.Message {
	message := gomail.NewMessage()
	message.SetHeader(constants.FromAddress, fromAddress)
	message.SetHeader(constants.Recipient, request.Recipient)
	message.SetHeader(constants.EmailSubject, subject)
	message.SetBody(constants.HTMLBody, body)

	return message
}
