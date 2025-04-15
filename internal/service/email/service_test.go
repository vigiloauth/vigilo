package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	domain "github.com/vigiloauth/vigilo/internal/domain/email"
	"github.com/vigiloauth/vigilo/internal/errors"
	mocks "github.com/vigiloauth/vigilo/internal/mocks/email"
	"gopkg.in/gomail.v2"
)

func TestEmailService_SendEmail(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mailer := &mocks.MockGoMailer{
			NewMessageFunc: func(request *domain.EmailRequest, body, subject, fromAddress string) *gomail.Message {
				return gomail.NewMessage()
			},
			DialAndSendFunc: func(host string, port int, username, password string, message ...*gomail.Message) error {
				return nil
			},
		}

		config.GetServerConfig().SMTPConfig().SetHealth(true)
		request := createVerificationEmail()
		service := NewEmailService(mailer)

		err := service.SendEmail(request)
		assert.NoError(t, err)
	})

	t.Run("Email is added to retry queue when the SMTP server is down", func(t *testing.T) {
		config.GetServerConfig().SMTPConfig().SetHealth(false)
		request := createVerificationEmail()
		service := NewEmailService(nil)

		err := service.SendEmail(request)
		assert.NoError(t, err)

		// assert the queue contains one request
		retryQueue := service.GetEmailRetryQueue()
		assert.False(t, retryQueue.IsEmpty())
	})

	t.Run("Error is returned when the email fails to send", func(t *testing.T) {
		mailer := &mocks.MockGoMailer{
			NewMessageFunc: func(request *domain.EmailRequest, body, subject, fromAddress string) *gomail.Message {
				return gomail.NewMessage()
			},
			DialAndSendFunc: func(host string, port int, username, password string, message ...*gomail.Message) error {
				return errors.NewInternalServerError()
			},
		}

		config.GetServerConfig().SMTPConfig().SetHealth(true)
		request := createVerificationEmail()
		service := NewEmailService(mailer)

		err := service.SendEmail(request)
		assert.Error(t, err)

		// assert the queue contains one request
		retryQueue := service.GetEmailRetryQueue()
		assert.False(t, retryQueue.IsEmpty())
	})
}

func TestEmailService_TestConnection(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mailer := &mocks.MockGoMailer{
			DialFunc: func(host string, port int, username, password string) (gomail.SendCloser, error) {
				dialer := gomail.NewDialer(host, port, username, password)
				return dialer.Dial()
			},
		}

		config.GetServerConfig().SMTPConfig().SetHealth(true)
		service := NewEmailService(mailer)

		err := service.TestConnection()
		assert.NoError(t, err)
	})
}

func createVerificationEmail() *domain.EmailRequest {
	return &domain.EmailRequest{
		Recipient:         "test@mail.com",
		VerificationCode:  "1234",
		VerificationToken: "1234",
		EmailType:         domain.AccountVerification,
	}
}
