package domain

import "gopkg.in/gomail.v2"

type Mailer interface {
	Dial(host string, port int, username string, password string) (gomail.SendCloser, error)
	DialAndSend(host string, port int, username string, password string, message ...*gomail.Message) error
	NewMessage(request *EmailRequest, body string, subject string, fromAddress string) *gomail.Message
}
