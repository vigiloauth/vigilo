package mocks

import (
	domain "github.com/vigiloauth/vigilo/internal/domain/email"
	"gopkg.in/gomail.v2"
)

var _ domain.Mailer = (*MockGoMailer)(nil)

type MockGoMailer struct {
	DialFunc        func(host string, port int, username string, password string) (gomail.SendCloser, error)
	DialAndSendFunc func(host string, port int, username string, password string, message ...*gomail.Message) error
	NewMessageFunc  func(request *domain.EmailRequest, body string, subject string, fromAddress string) *gomail.Message
}

func (m *MockGoMailer) Dial(host string, port int, username string, password string) (gomail.SendCloser, error) {
	return m.DialFunc(host, port, username, password)
}

func (m *MockGoMailer) DialAndSend(host string, port int, username string, password string, message ...*gomail.Message) error {
	return m.DialAndSendFunc(host, port, username, password, message...)
}

func (m *MockGoMailer) NewMessage(request *domain.EmailRequest, body string, subject string, fromAddress string) *gomail.Message {
	return m.NewMessageFunc(request, body, subject, fromAddress)
}
