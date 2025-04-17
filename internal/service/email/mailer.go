package service

import (
	"github.com/vigiloauth/vigilo/internal/common"
	domain "github.com/vigiloauth/vigilo/internal/domain/email"
	"gopkg.in/gomail.v2"
)

var _ domain.Mailer = (*goMailer)(nil)

type goMailer struct{}

func NewGoMailer() domain.Mailer {
	return &goMailer{}
}

func (m *goMailer) Dial(host string, port int, username string, password string) (gomail.SendCloser, error) {
	dialer := gomail.NewDialer(host, port, username, password)
	return dialer.Dial()
}

func (m *goMailer) DialAndSend(host string, port int, username string, password string, message ...*gomail.Message) error {
	dialer := gomail.NewDialer(host, port, username, password)
	return dialer.DialAndSend(message...)
}

func (m *goMailer) NewMessage(request *domain.EmailRequest, body string, subject string, fromAddress string) *gomail.Message {
	message := gomail.NewMessage()
	message.SetHeader(common.FromAddress, fromAddress)
	message.SetHeader(common.Recipient, request.Recipient)
	message.SetHeader(common.EmailSubject, subject)
	message.SetBody(common.HTMLBody, body)

	return message
}
