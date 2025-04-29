package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/idp/config"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/email"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/email"
	"gopkg.in/gomail.v2"
)

func TestEmailService_SendEmail(t *testing.T) {
	ctx := context.Background()

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

		err := service.SendEmail(ctx, request)
		assert.NoError(t, err)
	})

	t.Run("Email is added to retry queue when the SMTP server is down", func(t *testing.T) {
		config.GetServerConfig().SMTPConfig().SetHealth(false)
		request := createVerificationEmail()
		service := NewEmailService(nil)

		err := service.SendEmail(ctx, request)
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

		err := service.SendEmail(ctx, request)
		assert.Error(t, err)

		// assert the queue contains one request
		retryQueue := service.GetEmailRetryQueue()
		assert.False(t, retryQueue.IsEmpty())
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
