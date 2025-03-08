package email

import (
	"testing"
	"time"

	smtpmock "github.com/mocktools/go-smtp-mock/v2"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
)

const (
	smtpServer        string = "localhost"
	smtpPort          int    = 2525
	invalidSMTPServer string = "invalid-smt-server.com"
	fromAddress       string = "no-reply@example.com"
	recipient         string = "user@example.com"
	applicationID     string = "TestApp"
	resetURL          string = "https://example.com/reset"
	resetToken        string = "token123"
)

func setupSMTPConfig() *config.SMTPConfig {
	smtpConfig := &config.SMTPConfig{}
	smtpConfig.SetServer(smtpServer)
	smtpConfig.SetPort(smtpPort)
	smtpConfig.SetFromAddress(fromAddress)
	smtpConfig.SetEncryption(config.None)

	return smtpConfig
}

func createRequest() EmailRequest {
	return EmailRequest{
		Recipient:     recipient,
		ApplicationID: applicationID,
		ResetURL:      resetURL,
		ResetToken:    resetToken,
	}
}

func TestNewPasswordResetService_ValidSMTPConfig(t *testing.T) {
	smtpConfig := setupSMTPConfig()

	ps, err := NewPasswordResetService(smtpConfig)
	assert.NoError(t, err)
	assert.NotNil(t, ps)
}

func TestNewPasswordResetService_InvalidSMTPConfig(t *testing.T) {
	invalidSMTPConfig := setupSMTPConfig()
	invalidSMTPConfig.SetPort(0)
	invalidSMTPConfig.SetServer("")

	ps, err := NewPasswordResetService(invalidSMTPConfig)
	assert.Error(t, err)
	assert.Nil(t, ps)
}

func TestGenerateEmail(t *testing.T) {
	smtpConfig := setupSMTPConfig()
	ps, _ := NewPasswordResetService(smtpConfig)

	request := createRequest()
	emailRequest := ps.GenerateEmail(request)

	assert.Equal(t, request.Recipient, emailRequest.Recipient)
	assert.Contains(t, emailRequest.Subject, "Password Reset Request")
	assert.Contains(t, emailRequest.TemplateData["ResetURL"], resetURL)
}

func TestSendEmail_Failure(t *testing.T) {
	smtpConfig := setupSMTPConfig()
	ps, _ := NewPasswordResetService(smtpConfig)

	request := createRequest()
	err := ps.SendEmail(request)
	assert.Error(t, err)
}

func TestTestConnection_Success(t *testing.T) {
	smtpConfig := setupSMTPConfig()
	ps, _ := NewPasswordResetService(smtpConfig)

	cfg := smtpmock.ConfigurationAttr{
		HostAddress:       smtpServer,
		PortNumber:        smtpPort,
		LogToStdout:       true,
		LogServerActivity: true,
	}

	server := smtpmock.New(cfg)
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start mock SMTP server: %v", err)
	}
	defer server.Stop()

	err := ps.TestConnection()
	assert.NoError(t, err)
}

func TestTestConnection_Failure(t *testing.T) {
	smtpConfig := setupSMTPConfig()
	ps, _ := NewPasswordResetService(smtpConfig)

	err := ps.TestConnection()
	assert.Error(t, err)
}

func TestProcessQueue_EmptyQueue(t *testing.T) {
	smtpConfig := setupSMTPConfig()
	ps, _ := NewPasswordResetService(smtpConfig)

	ps.ProcessQueue() // Should not panic or throw any error
}

func TestProcessQueue_Retry(t *testing.T) {
	smtpConfig := setupSMTPConfig()
	smtpConfig.SetMaxRetries(2)
	smtpConfig.SetRetryDelay(1 * time.Second)

	ps, _ := NewPasswordResetService(smtpConfig)

	request := createRequest()
	ps.SendEmail(request)
	ps.ProcessQueue()

	queueStatus, _ := ps.GetQueueStatus()
	assert.Equal(t, 1, queueStatus)
}

func TestStartQueueProcessor(t *testing.T) {
	smtpConfig := setupSMTPConfig()
	smtpConfig.SetFromAddress(fromAddress)
	smtpConfig.SetEncryption(config.StartTLS)
	smtpConfig.SetRetryDelay(1 * time.Second)

	ps, _ := NewPasswordResetService(smtpConfig)

	go ps.StartQueueProcessor(2 * time.Second)
	time.Sleep(5 * time.Second)

	status, _ := ps.GetQueueStatus()
	assert.Equal(t, 0, status)
}
